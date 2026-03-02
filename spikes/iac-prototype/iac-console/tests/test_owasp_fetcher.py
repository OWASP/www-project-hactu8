import json
import os
import sys
import tempfile
import unittest
from unittest import mock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services import owasp_fetcher


class TestOwaspFetcherRepos(unittest.TestCase):
    def test_load_prefers_json_file(self) -> None:
        data = [{"owner": "OWASP", "repo": "www-project-test"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            json.dump(data, handle)
            file_path = handle.name

        try:
            with mock.patch.dict(
                os.environ,
                {"OWASP_REPOS_PATH": file_path, "OWASP_REPOS_DISCOVER": "1"}
            ):
                with mock.patch.object(owasp_fetcher, "_discover_owasp_repos") as discover:
                    result = owasp_fetcher._load_owasp_repos()
                    self.assertEqual(result, data)
                    discover.assert_not_called()
        finally:
            os.unlink(file_path)

    def test_discovery_filters_prefix(self) -> None:
        repo1 = {
            "name": "www-project-alpha",
            "description": "alpha",
            "owner": {"login": "OWASP"}
        }
        repo2 = {
            "name": "not-a-project",
            "description": "skip",
            "owner": {"login": "OWASP"}
        }
        repo3 = {
            "name": "www-project-beta",
            "description": None,
            "owner": {"login": "OWASP"}
        }

        response1 = mock.MagicMock()
        response1.status_code = 200
        response1.json.return_value = [repo1, repo2]
        response1.headers = {
            "Link": "<https://api.github.com/orgs/OWASP/repos?page=2>; rel=\"next\""
        }

        response2 = mock.MagicMock()
        response2.status_code = 200
        response2.json.return_value = [repo3]
        response2.headers = {}

        client = mock.MagicMock()
        client.get.side_effect = [response1, response2]

        client_cm = mock.MagicMock()
        client_cm.__enter__.return_value = client
        client_cm.__exit__.return_value = False

        with mock.patch.dict(os.environ, {"OWASP_REPOS_DISCOVER": "1"}):
            with mock.patch("services.owasp_fetcher.httpx.Client", return_value=client_cm):
                result = owasp_fetcher._discover_owasp_repos()

        self.assertEqual(
            [repo["repo"] for repo in result],
            ["www-project-alpha", "www-project-beta"]
        )


if __name__ == "__main__":
    unittest.main()
