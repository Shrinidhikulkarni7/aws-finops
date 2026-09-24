"""Check the scanner's response-field assumptions against the AWS CLI's own
bundled service models (botocore data), independently of tests/fake_aws.

Skipped when the AWS CLI v2 models can't be found. Set AWS_CLI_DATA_DIR to the
botocore `data` directory to point at a specific install.
"""
import glob
import json
import os
import unittest

CANDIDATES = [
    os.environ.get("AWS_CLI_DATA_DIR", ""),
    "/usr/local/aws-cli/awscli/botocore/data",                      # macOS pkg installer
    "/usr/local/aws-cli/v2/current/dist/awscli/botocore/data",      # Linux installer
    "/opt/homebrew/opt/awscli/libexec/lib/python*/site-packages/awscli/botocore/data",
    "/usr/local/opt/awscli/libexec/lib/python*/site-packages/awscli/botocore/data",
]


def data_dir():
    for c in CANDIDATES:
        for d in glob.glob(c) if c else []:
            if os.path.isdir(os.path.join(d, "ec2")):
                return d
    return None


DATA = data_dir()


CLI_TO_MODEL = {"configservice": "config"}  # CLI command name -> botocore model directory


def model(service):
    service = CLI_TO_MODEL.get(service, service)
    paths = sorted(glob.glob(os.path.join(DATA, service, "*", "service-2.json")))
    with open(paths[-1]) as fh:
        return json.load(fh)


def output_has(service, op, path, input_=False):
    """True if dotted `path` (list members transparent) exists in op's output (or input) shape."""
    m = model(service)
    shape = m["operations"][op]["input" if input_ else "output"]["shape"]
    for part in path.split("."):
        sh = m["shapes"][shape]
        while sh["type"] == "list":
            sh = m["shapes"][sh["member"]["shape"]]
        if sh["type"] != "structure" or part not in sh["members"]:
            return False
        shape = sh["members"][part]["shape"]
    return True


def enum(service, shape):
    return model(service)["shapes"][shape].get("enum", [])


@unittest.skipUnless(DATA, "AWS CLI v2 service models not found")
class TestApiShapes(unittest.TestCase):
    # (service, operation, dotted path the scanner reads)
    OUTPUT_FIELDS = [
        ("eks", "DescribeClusterVersions", "clusterVersions.clusterVersion"),
        ("eks", "DescribeClusterVersions", "clusterVersions.status"),
        ("eks", "DescribeClusterVersions", "clusterVersions.endOfStandardSupportDate"),
        ("eks", "DescribeCluster", "cluster.upgradePolicy.supportType"),
        ("compute-optimizer", "GetEnrollmentStatus", "status"),
        ("compute-optimizer", "GetIdleRecommendations", "idleRecommendations.resourceId"),
        ("compute-optimizer", "GetIdleRecommendations", "idleRecommendations.resourceType"),
        ("compute-optimizer", "GetIdleRecommendations", "idleRecommendations.finding"),
        ("compute-optimizer", "GetIdleRecommendations",
         "idleRecommendations.savingsOpportunityAfterDiscounts.estimatedMonthlySavings.value"),
        ("compute-optimizer", "GetIdleRecommendations",
         "idleRecommendations.savingsOpportunity.estimatedMonthlySavings.value"),
        ("cost-optimization-hub", "ListRecommendationSummaries", "items.group"),
        ("cost-optimization-hub", "ListRecommendationSummaries", "items.recommendationCount"),
        ("cost-optimization-hub", "ListRecommendationSummaries", "items.estimatedMonthlySavings"),
        ("cost-optimization-hub", "ListRecommendationSummaries", "estimatedTotalDedupedSavings"),
        ("cost-optimization-hub", "ListRecommendations", "items.currentResourceType"),
        ("cost-optimization-hub", "ListRecommendations", "items.actionType"),
        ("cost-optimization-hub", "ListRecommendations", "items.estimatedMonthlySavings"),
        ("cost-optimization-hub", "ListRecommendations", "items.implementationEffort"),
        ("ce", "GetSavingsPlansPurchaseRecommendation",
         "SavingsPlansPurchaseRecommendation.SavingsPlansPurchaseRecommendationSummary.EstimatedMonthlySavingsAmount"),
        ("ce", "GetSavingsPlansUtilization", "Total.Utilization.UtilizationPercentage"),
        ("ce", "GetSavingsPlansCoverage", "SavingsPlansCoverages.Coverage.CoveragePercentage"),
        ("ce", "GetReservationUtilization", "Total.UtilizationPercentage"),
        ("ce", "GetAnomalies", "Anomalies.RootCauses.UsageType"),
        ("ce", "GetAnomalies", "Anomalies.Impact.TotalImpact"),
        ("ec2", "DescribeSnapshots", "Snapshots.StorageTier"),
        ("ec2", "DescribeInstances", "Reservations.Instances.StateTransitionReason"),
        ("ec2", "DescribeNatGateways", "NatGateways.VpcId"),
        ("rds", "DescribeDBInstances", "DBInstances.StorageType"),
        ("rds", "DescribeDBClusters", "DBClusters.StorageType"),
        ("dynamodb", "DescribeTable", "Table.BillingModeSummary.BillingMode"),
        ("application-autoscaling", "DescribeScalableTargets", "ScalableTargets.ResourceId"),
        ("logs", "DescribeLogGroups", "logGroups.retentionInDays"),
        ("logs", "DescribeLogGroups", "logGroups.storedBytes"),
        ("lambda", "ListFunctions", "Functions.Architectures"),
        ("secretsmanager", "ListSecrets", "SecretList.LastAccessedDate"),
        ("configservice", "DescribeConfigurationRecorders", "ConfigurationRecorders.recordingMode.recordingFrequency"),
        ("cloudtrail", "GetEventSelectors", "AdvancedEventSelectors.FieldSelectors.Equals"),
        ("route53", "ListHostedZones", "HostedZones.ResourceRecordSetCount"),
    ]
    INPUT_FIELDS = [
        ("eks", "DescribeClusterVersions", "includeAll"),
        ("cost-optimization-hub", "ListRecommendations", "orderBy.dimension"),
        ("cost-optimization-hub", "ListRecommendationSummaries", "groupBy"),
    ]

    def test_output_fields_exist(self):
        missing = [f for f in self.OUTPUT_FIELDS if not output_has(*f)]
        self.assertEqual(missing, [], "scanner reads fields the API model doesn't define")

    def test_input_fields_exist(self):
        missing = [f for f in self.INPUT_FIELDS if not output_has(*f, input_=True)]
        self.assertEqual(missing, [])

    def test_eks_status_values(self):
        m = model("eks")
        status_shape = m["shapes"]["ClusterVersionInformation"]["members"]["status"]["shape"]
        self.assertIn("extended-support", m["shapes"][status_shape].get("enum", []))

    def test_database_savings_plan_support_reported(self):
        # Not a failure: older CLIs lack DATABASE_SP and the scanner downgrades that to a warning.
        if "DATABASE_SP" not in enum("ce", "SupportedSavingsPlansType"):
            self.skipTest("installed AWS CLI predates DATABASE_SP; scanner warns instead of erroring")


if __name__ == "__main__":
    unittest.main()
