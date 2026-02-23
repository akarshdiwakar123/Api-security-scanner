import jwt
from rich import print


class AuthHandler:
    def __init__(self, token=None):
        self.token = token

    def get_auth_header(self):
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def decode_jwt(self):
        if not self.token:
            print("[yellow]No token provided.[/yellow]")
            return None

        try:
            decoded = jwt.decode(
                self.token,
                options={"verify_signature": False}
            )
            print("[green]JWT Decoded Successfully:[/green]")
            for key, value in decoded.items():
                print(f"[cyan]{key}[/cyan]: {value}")
            return decoded

        except Exception as e:
            print(f"[red]Failed to decode JWT: {e}[/red]")
            return None