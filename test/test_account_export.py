import base64
import json
import unittest
from typing import Any
from unittest.mock import patch

from services.account_service import AccountService


class MemoryStorage:
    def __init__(self, accounts: list[dict[str, Any]] | None = None) -> None:
        self.accounts = list(accounts or [])

    def load_accounts(self) -> list[dict[str, Any]]:
        return list(self.accounts)

    def save_accounts(self, accounts: list[dict[str, Any]]) -> None:
        self.accounts = list(accounts)

    def load_auth_keys(self) -> list[dict[str, Any]]:
        return []

    def save_auth_keys(self, auth_keys: list[dict[str, Any]]) -> None:
        pass

    def health_check(self) -> dict[str, Any]:
        return {"ok": True}

    def get_backend_info(self) -> dict[str, Any]:
        return {"type": "memory"}


def make_jwt(payload: dict[str, Any]) -> str:
    def encode(value: dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f'{encode({"alg": "none", "typ": "JWT"})}.{encode(payload)}.sig'


class AccountExportTests(unittest.TestCase):
    def test_build_export_items_uses_codex_shape_and_jwt_claims(self) -> None:
        access_token = make_jwt(
            {
                "exp": 0,
                "iat": 3600,
                "https://api.openai.com/auth": {"chatgpt_account_id": "acct_123"},
                "https://api.openai.com/profile": {"email": "test@example.com"},
            }
        )
        id_token = make_jwt({"email": "fallback@example.com"})
        service = AccountService(
            MemoryStorage(
                [
                    {
                        "access_token": access_token,
                        "id_token": id_token,
                        "refresh_token": "rt_test",
                    }
                ]
            )
        )

        [item] = service.build_export_items([access_token])

        self.assertEqual(item["type"], "codex")
        self.assertEqual(item["email"], "test@example.com")
        self.assertEqual(item["expired"], "1970-01-01T08:00:00+08:00")
        self.assertEqual(item["account_id"], "acct_123")
        self.assertEqual(item["access_token"], access_token)
        self.assertEqual(item["last_refresh"], "1970-01-01T09:00:00+08:00")
        self.assertEqual(item["id_token"], id_token)
        self.assertEqual(item["refresh_token"], "rt_test")

    def test_build_export_items_skips_accounts_missing_complete_tokens(self) -> None:
        complete_access_token = make_jwt({"exp": 0})
        complete_id_token = make_jwt({"email": "complete@example.com"})
        service = AccountService(
            MemoryStorage(
                [
                    {"access_token": "only_access"},
                    {"access_token": "missing_id", "refresh_token": "rt_missing_id"},
                    {"access_token": complete_access_token, "id_token": complete_id_token, "refresh_token": "rt_complete"},
                ]
            )
        )

        items = service.build_export_items()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["access_token"], complete_access_token)
        self.assertEqual(items[0]["id_token"], complete_id_token)
        self.assertEqual(items[0]["refresh_token"], "rt_complete")

    def test_add_account_items_preserves_export_fields_without_overwriting_plan_type(self) -> None:
        service = AccountService(MemoryStorage())

        result = service.add_account_items(
            [
                {
                    "type": "codex",
                    "access_token": "access_token_test",
                    "refresh_token": "rt_test",
                    "account_id": "acct_123",
                }
            ]
        )

        account = service.get_account("access_token_test")
        self.assertEqual(result["added"], 1)
        self.assertIsNotNone(account)
        self.assertEqual(account["type"], "free")
        self.assertEqual(account["export_type"], "codex")
        self.assertEqual(account["refresh_token"], "rt_test")
        self.assertEqual(account["account_id"], "acct_123")

    def test_refresh_oauth_account_replaces_access_token_key(self) -> None:
        old_access_token = make_jwt({"exp": 0})
        new_access_token = make_jwt({"exp": 4102444800})
        service = AccountService(
            MemoryStorage(
                [
                    {
                        "access_token": old_access_token,
                        "refresh_token": "rt_old",
                        "id_token": "id_old",
                    }
                ]
            )
        )

        with patch(
            "services.account_service._refresh_codex_oauth_token",
            return_value={
                "access_token": new_access_token,
                "refresh_token": "rt_new",
                "id_token": "id_new",
                "expired": "2100-01-01T00:00:00+00:00",
                "email": "new@example.com",
            },
        ) as refresh:
            resolved = service.refresh_oauth_account(old_access_token, force=True)

        refresh.assert_called_once_with("rt_old")
        self.assertEqual(resolved, new_access_token)
        self.assertIsNone(service.get_account(old_access_token))
        account = service.get_account(new_access_token)
        self.assertIsNotNone(account)
        self.assertEqual(account["refresh_token"], "rt_new")
        self.assertEqual(account["id_token"], "id_new")
        self.assertEqual(account["email"], "new@example.com")

    def test_get_text_access_token_refreshes_expired_oauth_account(self) -> None:
        old_access_token = make_jwt({"exp": 0})
        new_access_token = make_jwt({"exp": 4102444800})
        service = AccountService(
            MemoryStorage(
                [
                    {
                        "access_token": old_access_token,
                        "refresh_token": "rt_old",
                        "status": "正常",
                    }
                ]
            )
        )

        with patch(
            "services.account_service._refresh_codex_oauth_token",
            return_value={
                "access_token": new_access_token,
                "refresh_token": "rt_new",
                "expired": "2100-01-01T00:00:00+00:00",
            },
        ):
            self.assertEqual(service.get_text_access_token(), new_access_token)


if __name__ == "__main__":
    unittest.main()
