from django.core.management.base import BaseCommand
from django.db import connection
from django.db.utils import OperationalError, ProgrammingError

class Command(BaseCommand):
    help = "Checks the PostgreSQL database connection"

    def handle(self, *args, **options):
        try:
            self.stdout.write("Attempting to connect to PostgreSQL...")
            # connection.ensure_connection()  # Removed this
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1;")  # Simple query to test connection
                result = cursor.fetchone()
                if result and result[0] == 1:
                    self.stdout.write(self.style.SUCCESS("Successfully connected to the database!"))
                else:
                    self.stdout.write(self.style.ERROR("Failed to connect to the database: Unexpected result from query."))
        except OperationalError as e:
            self.stderr.write(self.style.ERROR(f"Connection failed: {e}"))
            self.stderr.write(self.style.NOTICE("Possible solutions:"))
            self.stderr.write("1.  Verify your DATABASE_URL in settings.py and .env (if used).")
            self.stderr.write("2.  Check if the PostgreSQL server is running.")
            self.stderr.write("3.  Ensure the database name, username, and password are correct.")
            self.stderr.write("4.  Check network connectivity to the server.")
            if "SSL" in str(e):
                self.stderr.write("5.  Ensure SSL/TLS is configured correctly (if required).")
        except ProgrammingError as e:
            self.stderr.write(self.style.ERROR(f"ProgrammingError: {e}"))
            self.stderr.write(self.style.NOTICE("Possible solutions:"))
            self.stderr.write("1. Verify that the database exists.")
            self.stderr.write("2. Check the SQL syntax (though the query is very simple).")

