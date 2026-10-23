package io.github.hectorvent.floci.services.eks;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.PaginatedResult;
import io.github.hectorvent.floci.core.common.Pagination;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.eks.model.AccessEntry;
import io.github.hectorvent.floci.services.eks.model.AccessPolicy;
import io.github.hectorvent.floci.services.eks.model.AccessScope;
import io.github.hectorvent.floci.services.eks.model.AssociateAccessPolicyRequest;
import io.github.hectorvent.floci.services.eks.model.AssociatedAccessPolicy;
import io.github.hectorvent.floci.services.eks.model.Cluster;
import io.github.hectorvent.floci.services.eks.model.ClusterStatus;
import io.github.hectorvent.floci.services.eks.model.CreateAccessEntryRequest;
import io.github.hectorvent.floci.services.eks.model.UpdateAccessEntryRequest;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.IamUser;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;

/** Access entries and their access-policy associations, which the cluster webhooks authenticate and authorize by. */
@ApplicationScoped
public class EksAccessEntryService {
    private static final List<String> ACCESS_POLICY_NAMES = List.of(
            "AWSBackupFullAccessPolicyForBackup", "AWSBackupFullAccessPolicyForRestore",
            "AmazonAIOpsAssistantPolicy", "AmazonARCRegionSwitchScalingPolicy", "AmazonEKSACKPolicy",
            "AmazonEKSAdminPolicy", "AmazonEKSAdminViewPolicy", "AmazonEKSArgoCDClusterPolicy",
            "AmazonEKSArgoCDPolicy", "AmazonEKSAutoNodePolicy", "AmazonEKSBlockStorageClusterPolicy",
            "AmazonEKSBlockStoragePolicy", "AmazonEKSClusterAdminPolicy", "AmazonEKSClusterInsightsPolicy",
            "AmazonEKSComputeClusterPolicy", "AmazonEKSComputePolicy", "AmazonEKSEditPolicy",
            "AmazonEKSHybridPolicy", "AmazonEKSKROPolicy", "AmazonEKSLoadBalancingClusterPolicy",
            "AmazonEKSLoadBalancingPolicy", "AmazonEKSNetworkingClusterPolicy", "AmazonEKSNetworkingPolicy",
            "AmazonEKSPodIdentityPolicy", "AmazonEKSSecretAdminPolicy", "AmazonEKSSecretReaderPolicy",
            "AmazonEKSViewPolicy");
    static final String CLUSTER_ADMIN_POLICY = "AmazonEKSClusterAdminPolicy";
    private static final int MAX_PAGE_SIZE = 100;

    private final StorageBackend<String, StoredEntry> entries;
    private final IamService iam;
    private final Clock clock;

    @Inject
    public EksAccessEntryService(StorageFactory factory, IamService iam) {
        this(factory.create("eks", "eks-access-entries.json", new TypeReference<Map<String, StoredEntry>>() {}), iam);
    }

    EksAccessEntryService(StorageBackend<String, StoredEntry> entries, IamService iam) {
        this(entries, iam, Clock.systemUTC());
    }

    EksAccessEntryService(StorageBackend<String, StoredEntry> entries, IamService iam, Clock clock) {
        this.entries = entries;
        this.iam = iam;
        this.clock = clock;
    }

    @RegisterForReflection
    public record StoredEntry(AccessEntry entry, String principalId, String clientRequestToken,
                              List<AssociatedAccessPolicy> accessPolicies) {
        public StoredEntry {
            accessPolicies = accessPolicies == null ? List.of() : List.copyOf(accessPolicies);
        }
    }

    @RegisterForReflection
    public record Page(List<String> accessEntries, String nextToken) {}

    @RegisterForReflection
    public record PolicyPage(List<AssociatedAccessPolicy> associatedAccessPolicies, String nextToken) {}

    public synchronized AssociatedAccessPolicy associate(Cluster cluster, String principal,
                                                         AssociateAccessPolicyRequest request) {
        StoredEntry stored = storedEntry(cluster, principal);
        if (request == null || request.policyArn() == null) {
            throw invalid("policyArn is required");
        }
        requireAccessPolicyArn(cluster, request.policyArn());
        AccessScope scope = accessScope(request.accessScope());
        if (!"STANDARD".equals(stored.entry().type())) {
            throw new AwsException("InvalidRequestException",
                    "Access policies can only be associated with STANDARD access entries", 400);
        }
        double now = clock.millis() / 1000.0;
        double associatedAt = stored.accessPolicies().stream()
                .filter(existing -> existing.policyArn().equals(request.policyArn()))
                .mapToDouble(AssociatedAccessPolicy::associatedAt).findFirst().orElse(now);
        AssociatedAccessPolicy association = new AssociatedAccessPolicy(request.policyArn(), scope, associatedAt, now);
        List<AssociatedAccessPolicy> policies = new ArrayList<>(stored.accessPolicies());
        policies.removeIf(existing -> existing.policyArn().equals(request.policyArn()));
        policies.add(association);
        policies.sort(Comparator.comparing(AssociatedAccessPolicy::policyArn));
        entries.put(prefix(cluster) + principal, new StoredEntry(stored.entry(), stored.principalId(),
                stored.clientRequestToken(), policies));
        return association;
    }

    public synchronized PolicyPage listAccessPolicies(Cluster cluster, String principal, Integer maxResults,
                                                      String nextToken) {
        List<AssociatedAccessPolicy> policies = storedEntry(cluster, principal).accessPolicies();
        // The newline ends the principal, so a token for role/a:b is not read as one for role/a.
        PaginatedResult<AssociatedAccessPolicy> page = Pagination.paginate(policies, AssociatedAccessPolicy::policyArn,
                pageSize(maxResults), nextToken, "policies:" + prefix(cluster) + principal + "\n",
                token -> invalid("Invalid nextToken"));
        return new PolicyPage(page.items(), page.nextToken());
    }

    public synchronized void disassociate(Cluster cluster, String principal, String policyArn) {
        StoredEntry stored = storedEntry(cluster, principal);
        requireAccessPolicyArn(cluster, policyArn);
        List<AssociatedAccessPolicy> policies = stored.accessPolicies().stream()
                .filter(existing -> !existing.policyArn().equals(policyArn)).toList();
        if (policies.size() == stored.accessPolicies().size()) {
            return; // EKS documents no error for a policy the entry does not hold
        }
        entries.put(prefix(cluster) + principal, new StoredEntry(stored.entry(), stored.principalId(),
                stored.clientRequestToken(), policies));
    }

    public PaginatedResult<AccessPolicy> listAccessPolicies(String partition, Integer maxResults, String nextToken) {
        List<AccessPolicy> policies = ACCESS_POLICY_NAMES.stream()
                .map(name -> new AccessPolicy(name, accessPolicyArn(partition, name))).toList();
        return Pagination.paginate(policies, AccessPolicy::name, maxResults, nextToken, MAX_PAGE_SIZE,
                "InvalidParameterException");
    }

    static String accessPolicyArn(String partition, String name) {
        return "arn:" + partition + ":eks::aws:cluster-access-policy/" + name;
    }

    private StoredEntry storedEntry(Cluster cluster, String principal) {
        requireApiAccess(cluster);
        return entries.get(prefix(cluster) + principal)
                .orElseThrow(() -> new AwsException("ResourceNotFoundException", "Access entry not found", 404));
    }

    private static AccessScope accessScope(AccessScope scope) {
        if (scope == null || scope.type() == null) {
            throw invalid("accessScope.type is required");
        }
        List<String> namespaces = scope.namespaces() == null ? List.of() : scope.namespaces();
        if ("cluster".equals(scope.type())) {
            if (!namespaces.isEmpty()) {
                throw invalid("namespaces can only be specified for a namespace access scope");
            }
            return new AccessScope("cluster", List.of());
        }
        if (!"namespace".equals(scope.type())) {
            throw invalid("accessScope.type must be cluster or namespace");
        }
        if (namespaces.isEmpty() || namespaces.stream().anyMatch(namespace -> namespace == null || namespace.isBlank())) {
            throw invalid("A namespace access scope requires nonempty namespace names");
        }
        // Terraform models namespaces as a set, so a repeated name must not come back twice.
        return new AccessScope("namespace", List.copyOf(new LinkedHashSet<>(namespaces)));
    }

    public synchronized AccessEntry create(Cluster cluster, CreateAccessEntryRequest request) {
        requireApiAccess(cluster);
        if (request == null || request.principalArn() == null) {
            throw invalid("principalArn is required");
        }
        String type = request.type() == null ? "STANDARD" : request.type();
        if (!"STANDARD".equals(type) && !"EC2_LINUX".equals(type)) {
            throw invalid("Floci currently supports STANDARD and EC2_LINUX access entries");
        }
        boolean node = "EC2_LINUX".equals(type);
        if (node && (request.username() != null || request.kubernetesGroups() != null)) {
            throw invalid("EC2_LINUX entries cannot specify username or kubernetesGroups");
        }
        String principal = request.principalArn();
        AwsArnUtils.Arn arn = AwsArnUtils.isArn(principal) ? AwsArnUtils.parse(principal) : null;
        AwsArnUtils.Arn clusterArn = AwsArnUtils.parse(cluster.getArn());
        if (arn == null || !arn.partition().equals(clusterArn.partition())
                || !"iam".equals(arn.service()) || !arn.region().isEmpty() || !arn.accountId().matches("[0-9]{12}")
                || !(arn.resource().startsWith("role/") || (!node && arn.resource().startsWith("user/")))
                || arn.resource().startsWith("role/aws-service-role/")
                || principal.endsWith("/") || (node && !arn.accountId().equals(clusterArn.accountId()))) {
            throw invalid("principalArn must identify an IAM principal; EC2_LINUX requires a role in the cluster account");
        }
        String name = principal.substring(principal.lastIndexOf('/') + 1);
        boolean role = arn.resource().startsWith("role/");
        String principalId = role
                ? iam.findRole(arn.accountId(), name).filter(value -> principal.equals(value.getArn()))
                        .map(IamRole::getRoleId).orElseThrow(() -> invalid("IAM role does not exist"))
                : iam.findUser(arn.accountId(), name).filter(value -> principal.equals(value.getArn()))
                        .map(IamUser::getUserId).orElseThrow(() -> invalid("IAM user does not exist"));
        String username = node ? "system:node:{{EC2PrivateDNSName}}" : request.username();
        if (username != null && !node && (username.isBlank()
                || username.matches("^(system|eks|aws|amazon|iam):.*"))) {
            throw invalid("Invalid username");
        }
        if (username != null && !node) {
            for (String placeholder : List.of("{{SessionName}}", "{{SessionNameRaw}}")) {
                int position = username.indexOf(placeholder);
                if (position >= 0 && !username.substring(0, position).contains(":")) {
                    throw invalid("A session-name placeholder must be preceded by a colon");
                }
            }
        }
        if (username == null) {
            username = role ? AwsArnUtils.Arn.global(arn.partition(), "sts", arn.accountId(),
                    "assumed-role/" + name + "/{{SessionName}}").toString() : principal;
        }
        List<String> groups = node ? List.of("system:nodes")
                : request.kubernetesGroups() == null ? List.of() : request.kubernetesGroups();
        if (groups.stream().anyMatch(group -> group == null || group.isBlank())) {
            throw invalid("kubernetesGroups must contain nonempty strings");
        }
        Map<String, String> tags = request.tags() == null ? Map.of() : request.tags();
        if (tags.size() > 50 || tags.entrySet().stream().anyMatch(tag -> tag.getKey() == null
                || tag.getKey().isEmpty() || tag.getKey().length() > 128 || tag.getValue() == null
                || tag.getValue().length() > 256)) {
            throw invalid("Invalid access entry tags");
        }
        String prefix = prefix(cluster);
        String token = request.clientRequestToken();
        if (token != null) {
            for (StoredEntry stored : entries.scan(key -> key.startsWith(prefix))) {
                if (token.equals(stored.clientRequestToken())) {
                    AccessEntry previous = stored.entry();
                    if (principal.equals(previous.principalArn()) && type.equals(previous.type())
                            && username.equals(previous.username()) && groups.equals(previous.kubernetesGroups())
                            && tags.equals(previous.tags())) {
                        return previous;
                    }
                    throw invalid("clientRequestToken was already used with different parameters");
                }
            }
        }
        String key = prefix + principal;
        if (entries.get(key).isPresent()) {
            throw new AwsException("ResourceInUseException", "Access entry already exists", 409);
        }
        double now = clock.millis() / 1000.0;
        String entryArn = new AwsArnUtils.Arn(clusterArn.partition(), "eks", clusterArn.region(), clusterArn.accountId(),
                "access-entry/" + cluster.getName() + "/" + (role ? "role" : "user") + "/" + arn.accountId() + "/" + name
                        + "/" + UUID.randomUUID()).toString();
        AccessEntry entry = new AccessEntry(entryArn, cluster.getName(), principal,
                type, username, List.copyOf(groups), Map.copyOf(tags), now, now);
        entries.put(key, new StoredEntry(entry, principalId, token, List.of()));
        return entry;
    }

    public synchronized AccessEntry update(Cluster cluster, String principal, UpdateAccessEntryRequest request) {
        StoredEntry stored = storedEntry(cluster, principal);
        AccessEntry entry = stored.entry();
        List<String> groups = request == null ? null : request.kubernetesGroups();
        String username = request == null ? null : request.username();
        if (!"STANDARD".equals(entry.type()) && (groups != null || username != null)) {
            throw invalid(entry.type() + " entries cannot specify username or kubernetesGroups");
        }
        if (username != null) {
            requireValidUsername(username);
        }
        if (groups != null) {
            requireValidGroups(groups);
        }
        AccessEntry updated = new AccessEntry(entry.accessEntryArn(), entry.clusterName(), entry.principalArn(),
                entry.type(), username == null ? entry.username() : username,
                groups == null ? entry.kubernetesGroups() : List.copyOf(groups), entry.tags(), entry.createdAt(),
                clock.millis() / 1000.0);
        entries.put(prefix(cluster) + principal, new StoredEntry(updated, stored.principalId(),
                stored.clientRequestToken(), stored.accessPolicies()));
        return updated;
    }

    /** The policy name of an access-policy ARN, or null when the ARN names no access policy. */
    static String accessPolicyName(String policyArn) {
        int slash = policyArn == null ? -1 : policyArn.indexOf(":cluster-access-policy/");
        return slash < 0 ? null : policyArn.substring(slash + ":cluster-access-policy/".length());
    }

    /** The account root and IAM users and roles that signed the request; the root when none did. */
    String callerPrincipalArn(String accessKeyId, String partition, String accountId) {
        return Optional.ofNullable(accessKeyId).flatMap(iam::resolveCallerArns)
                .map(IamService.CallerArns::principalArn)
                .orElse(AwsArnUtils.Arn.global(partition, "iam", accountId, "root").toString());
    }

    /** The cluster creator's admin entry, which EKS creates whenever the cluster's mode includes API. */
    synchronized void bootstrapCreator(Cluster cluster, String principal) {
        String[] arn = principal == null ? new String[0] : principal.split(":", 6);
        if (arn.length != 6 || !"iam".equals(arn[2]) || !arn[4].matches("[0-9]{12}")) {
            return;
        }
        String key = prefix(cluster) + principal;
        if (getIn(cluster, key).isPresent()) {
            return;
        }
        String name = principal.substring(principal.lastIndexOf('/') + 1);
        String kind;
        String principalId;
        String username;
        if ("root".equals(arn[5])) {
            kind = "root";
            principalId = null;
            username = principal;
        } else if (arn[5].startsWith("role/")) {
            kind = "role";
            principalId = iam.findRole(arn[4], name).filter(value -> principal.equals(value.getArn()))
                    .map(IamRole::getRoleId).orElse(null);
            username = "arn:" + arn[1] + ":sts::" + arn[4] + ":assumed-role/" + name + "/{{SessionName}}";
        } else if (arn[5].startsWith("user/")) {
            kind = "user";
            principalId = iam.findUser(arn[4], name).filter(value -> principal.equals(value.getArn()))
                    .map(IamUser::getUserId).orElse(null);
            username = principal;
        } else {
            return;
        }
        if (principalId == null && !"root".equals(kind)) {
            return;
        }
        String[] clusterArn = cluster.getArn().split(":", 6);
        double now = clock.millis() / 1000.0;
        AccessEntry entry = new AccessEntry("arn:" + clusterArn[1] + ":eks:" + clusterArn[3] + ":"
                + clusterArn[4] + ":access-entry/" + cluster.getName() + "/" + kind + "/" + arn[4] + "/"
                + ("root".equals(kind) ? "" : name + "/") + UUID.randomUUID(), cluster.getName(), principal,
                "STANDARD", username, List.of(), Map.of(), now, now);
        String adminPolicy = accessPolicyArn(AwsArnUtils.parse(cluster.getArn()).partition(), CLUSTER_ADMIN_POLICY);
        AssociatedAccessPolicy admin = new AssociatedAccessPolicy(adminPolicy, new AccessScope("cluster", List.of()),
                now, now);
        putIn(cluster, key, new StoredEntry(entry, principalId, null, List.of(admin)));
    }

    /** The entry of this principal, provided it was created for the same IAM principal id. */
    synchronized Optional<StoredEntry> principalEntry(Cluster cluster, String principal, String principalId) {
        return getIn(cluster, prefix(cluster) + principal)
                .filter(stored -> Objects.equals(stored.principalId(), principalId));
    }

    synchronized Optional<StoredEntry> standardEntryById(Cluster cluster, String principalId) {
        String prefix = prefix(cluster);
        return scanIn(cluster, key -> key.startsWith(prefix)).stream()
                .filter(stored -> principalId.equals(stored.principalId()))
                .filter(stored -> "STANDARD".equals(stored.entry().type())).findFirst();
    }

    private Optional<StoredEntry> getIn(Cluster cluster, String key) {
        return entries instanceof AccountAwareStorageBackend<StoredEntry> aware
                ? aware.getForAccount(account(cluster), key) : entries.get(key);
    }

    private List<StoredEntry> scanIn(Cluster cluster, Predicate<String> keys) {
        return entries instanceof AccountAwareStorageBackend<StoredEntry> aware
                ? aware.scanForAccount(account(cluster), keys) : entries.scan(keys);
    }

    private void putIn(Cluster cluster, String key, StoredEntry value) {
        if (entries instanceof AccountAwareStorageBackend<StoredEntry> aware) {
            aware.putForAccount(account(cluster), key, value);
        } else {
            entries.put(key, value);
        }
    }

    private static String account(Cluster cluster) {
        return cluster.getArn().split(":", 6)[4];
    }
    synchronized Optional<AccessEntry> workerEntry(Cluster cluster, String accountId, String principal, String roleId) {
        requireApiAccess(cluster);
        String key = prefix(cluster) + principal;
        Optional<StoredEntry> stored = entries instanceof AccountAwareStorageBackend<StoredEntry> aware
                ? aware.getForAccount(accountId, key) : entries.get(key);
        return stored.filter(value -> roleId != null && roleId.equals(value.principalId()))
                .map(StoredEntry::entry).filter(entry -> "EC2_LINUX".equals(entry.type()));
    }

    public synchronized AccessEntry describe(Cluster cluster, String principal) {
        return storedEntry(cluster, principal).entry();
    }

    public synchronized void delete(Cluster cluster, String principal) {
        describe(cluster, principal);
        entries.delete(prefix(cluster) + principal);
    }

    public synchronized Page list(Cluster cluster, Integer maxResults, String nextToken) {
        return list(cluster, maxResults, nextToken, null);
    }

    public synchronized Page list(Cluster cluster, Integer maxResults, String nextToken, String associatedPolicyArn) {
        requireApiAccess(cluster);
        String prefix = prefix(cluster);
        List<String> principals = entries.scan(key -> key.startsWith(prefix)).stream()
                .filter(stored -> associatedPolicyArn == null || stored.accessPolicies().stream()
                        .anyMatch(policy -> policy.policyArn().equals(associatedPolicyArn)))
                .map(stored -> stored.entry().principalArn()).toList();
        PaginatedResult<String> page = Pagination.paginate(principals, principal -> principal, pageSize(maxResults),
                nextToken, "entries:" + prefix, token -> invalid("Invalid nextToken"));
        return new Page(page.items(), page.nextToken());
    }

    public synchronized void deleteClusterEntries(Cluster cluster) {
        String prefix = prefix(cluster);
        for (StoredEntry stored : entries.scan(key -> key.startsWith(prefix))) {
            entries.delete(prefix + stored.entry().principalArn());
        }
    }

    private static String prefix(Cluster cluster) {
        // A recreated cluster must not inherit access entries or pagination tokens from its predecessor.
        return cluster.getArn() + "/" + Objects.toString(cluster.getCreatedAt()) + "/";
    }

    private static void requireApiAccess(Cluster cluster) {
        if (cluster.getAccessConfig() == null || "CONFIG_MAP".equals(cluster.getAccessConfig().authenticationMode())) {
            throw new AwsException("InvalidRequestException", "Cluster authentication mode must be API or API_AND_CONFIG_MAP", 400);
        }
        if (cluster.getStatus() != ClusterStatus.ACTIVE) {
            throw new AwsException("InvalidRequestException", "Cluster must be ACTIVE", 400);
        }
    }

    private static int pageSize(Integer maxResults) {
        int limit = maxResults == null ? 100 : maxResults;
        if (limit < 1 || limit > 100) {
            throw invalid("maxResults must be between 1 and 100");
        }
        return limit;
    }

    private static void requireAccessPolicyArn(Cluster cluster, String policyArn) {
        AwsArnUtils.Arn arn;
        try {
            arn = AwsArnUtils.parse(policyArn);
        } catch (IllegalArgumentException e) {
            throw invalid("policyArn must identify an EKS cluster access policy");
        }
        boolean accessPolicy = arn.partition().equals(AwsArnUtils.parse(cluster.getArn()).partition())
                && arn.service().equals("eks")
                && arn.region().isEmpty()
                && arn.accountId().equals("aws") // partition-literal: the AWS-managed account, "aws" in every partition
                && arn.resource().matches("cluster-access-policy/[A-Za-z0-9]+");
        if (!accessPolicy) {
            throw invalid("policyArn must identify an EKS cluster access policy");
        }
    }

    private static void requireValidUsername(String username) {
        if (username.isBlank() || username.matches("^(system|eks|aws|amazon|iam):.*")) {
            throw invalid("Invalid username");
        }
        for (String placeholder : List.of("{{SessionName}}", "{{SessionNameRaw}}")) {
            int position = username.indexOf(placeholder);
            if (position >= 0 && !username.substring(0, position).contains(":")) {
                throw invalid("A session-name placeholder must be preceded by a colon");
            }
        }
    }

    private static void requireValidGroups(List<String> groups) {
        if (groups.stream().anyMatch(group -> group == null || group.isBlank())) {
            throw invalid("kubernetesGroups must contain nonempty strings");
        }
    }

    private static AwsException invalid(String message) {
        return new AwsException("InvalidParameterException", message, 400);
    }
}
