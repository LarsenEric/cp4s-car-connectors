import unittest
from unittest.mock import patch, Mock

from car_framework.context import context
from tests.test_utils import full_import_initialization, \
    GCPMockResponse, get_response


class TestAssetServer(unittest.TestCase):
    """Unit test for server access functions"""
    projects = None

    @patch('connector.server_access.resourcemanager_v3.services.projects.client.ProjectsClient.search_projects')
    @patch('connector.server_access.service_account.Credentials.from_service_account_info')
    def setUp(self, mock_account, mock_projects):
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        # Mock GCP credentials object
        mock_account.return_value.service_account_email = "cp4s@project.com"
        mock_account.return_value.signer_email = "cp4s@project.com"
        # Mock GCP project
        project_obj = Mock()
        project_obj.display_name = 'project'
        project_obj.project_id = 'cp4s_dev'
        mock_projects.return_value = [project_obj]
        self.projects = context().asset_server.set_credentials_and_projects()

    def test_set_credentials_and_project_list(self):
        """unit test for set_credentials_and_project_list"""
        assert self.projects is not None

    def test_set_credentials_and_project_list_error(self):
        """unit test for set_credentials_and_project_list"""
        try:
            error_response = None
            full_import_obj = full_import_initialization()
            full_import_obj.create_source_report_object()
            context().asset_server.set_credentials_and_projects()
        except Exception as ex:
            error_response = str(ex)
        assert error_response is not None

    @patch('connector.server_access.asset_v1.AssetServiceClient')
    def test_get_asset_list(self, mock_asset):
        """unit test for get_asset_list"""
        asset_list = None
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset.return_value.list_assets.return_value.list = get_response('vm_instances.json', True)
        mock_asset.return_value.list_assets.return_value.next_page_token = None
        asset_list = context().asset_server.get_asset_list("project", "compute", "resource")
        assert asset_list is not None

    @patch('connector.server_access.asset_v1.AssetServiceClient')
    def test_get_asset_list_error(self, mock_asset):
        """unit test for get_asset_list"""
        error_response = None
        try:
            full_import_obj = full_import_initialization()
            full_import_obj.create_source_report_object()
            mock_asset.return_value.list_assets.return_value = []
            mock_asset.return_value.list_assets.return_value.next_page_token = 10
            context().asset_server.get_asset_list("project", "compute", "resource")
        except Exception as e:
            error_response = str(e)
        assert error_response is not None

    @patch('connector.server_access.asset_v1.BatchGetAssetsHistoryResponse.to_json')
    @patch('connector.server_access.asset_v1.AssetServiceClient')
    def test_get_asset_history(self, mock_asset, mock_history):
        """unit test for get_asset_list"""
        asset_list = None
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset.return_value.batch_get_assets_history.return_value = []
        mock_history.return_value = b'{}'
        asset_list = context().asset_server.get_asset_history("project", "test", "resource", 1679238834)
        assert asset_list is not None

    @patch('connector.server_access.securitycenter.SecurityCenterClient')
    def test_get_vulnerabilities(self, mock_asset):
        """unit test for get_asset_list"""
        vuln_list = None
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset.return_value.list_findings.return_value.list = get_response('scc_response.json', True)
        mock_asset.return_value.list_findings.return_value.next_page_token = None
        vuln_list = context().asset_server.get_vulnerabilities("project")
        assert vuln_list is not None

    @patch('connector.server_access.AssetServer.get_asset_list')
    def test_get_vm_instances(self, mock_asset_list):
        """unit test for get_instances"""
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset_list.return_value = get_response('vm_instances.json', True)
        actual_response = context().asset_server.get_vm_instances('project')
        assert actual_response is not None

    @patch('connector.server_access.AssetServer.get_asset_list')
    def test_get_instances_pkgs(self, mock_asset_list):
        """unit test for get_instances"""
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset_list.return_value = get_response('vm_instance_os_pkgs.json', True)
        actual_response = context().asset_server.get_instances_pkgs('project')
        assert actual_response is not None

    @patch('connector.server_access.AssetServer.get_asset_list')
    def test_get_instance_vulnerabilities(self, mock_asset_list):
        """unit test for get_instances"""
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset_list.return_value = get_response('vm_instance_os_vuln.json', True)
        actual_response = context().asset_server.get_instance_vulnerabilities('project')
        assert actual_response is not None

    @patch('connector.server_access.AssetServer.set_credentials_and_projects')
    def test_connection(self, mock_connection):
        """unit test for test connection"""
        # Initialization
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()

        mock_connection.return_value = GCPMockResponse(200, [])
        context().asset_server.project_list = ['project']
        actual_response = context().asset_server.test_connection()
        assert actual_response is not None

    def test_connection_with_error(self):
        """unit test for test connection failure"""
        # Initialization
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        context().asset_server.project_list = ['project']
        actual_response = context().asset_server.test_connection()
        assert actual_response == 1

    @patch('connector.server_access.AssetServer.get_asset_list')
    def test_get_web_applications(self, mock_asset_list):
        """unit test for web application created"""
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset_list.return_value = get_response('web_app.json', True)
        actual_response = context().asset_server.get_web_applications('project')
        assert actual_response is not None

    @patch('connector.server_access.AssetServer.get_asset_list')
    def test_get_web_app_services(self, mock_asset_list):
        """unit test for web application services created"""
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset_list.return_value = get_response('web_app_service.json', True)
        actual_response = context().asset_server.get_web_app_services('project')
        assert actual_response is not None

    @patch('connector.server_access.AssetServer.get_asset_list')
    def get_web_app_service_versions(self, mock_asset_list):
        """unit test for web application service versions created"""
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_asset_list.return_value = get_response('web_app_service_version.json', True)
        actual_response = context().asset_server.web_app_service_versions('project')
        assert actual_response is not None

    @patch('connector.server_access.AssetServer.get_vulnerabilities')
    def test_get_scc_vulnerability(self, mock_vulnerabilities):
        """unit test for scc vulnerabilities"""
        full_import_obj = full_import_initialization()
        full_import_obj.create_source_report_object()
        mock_vulnerabilities.return_value = get_response('vulnerability.json', True)
        actual_response = context().asset_server.get_scc_vulnerability('project', 1679238834)
        assert actual_response is not None
