
# # your_app/middleware.py
# import logging
# from django.db import connection
# from django.conf import settings
# import threading
# import time

# logger = logging.getLogger(__name__)

# class NeonKeepAliveMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response
#         if getattr(settings, 'NEON_KEEPALIVE_ENABLED', True):
#             logger.info("Initializing Neon keep-alive middleware")
#             self.ping_thread = threading.Thread(
#                 target=self._keep_alive,
#                 daemon=True,
#                 name="neon_keepalive"
#             )
#             self.ping_thread.start()
#             logger.info("Started Neon keep-alive background thread")

#     def _keep_alive(self):
#         interval = getattr(settings, 'NEON_PING_INTERVAL', 240)
#         logger.info(f"Starting keep-alive pings every {interval} seconds")
        
#         while True:
#             try:
#                 with connection.cursor() as cursor:
#                     cursor.execute("SELECT 1, current_database(), now()")
#                     db_name, ping_time = cursor.fetchone()[1:]
#                     logger.debug(
#                         f"Neon ping successful | DB: {db_name} | Time: {ping_time}"
#                     )
#             except Exception as e:
#                 logger.error(
#                     "Neon ping failed",
#                     exc_info=True,  # This will log full traceback
#                     extra={'error': str(e)}
#                 )
#             time.sleep(interval)

#     def __call__(self, request):
#         return self.get_response(request)


















# your_app/middleware.py

# Coonect To NEODB
# PING NEO DB
import logging
from django.db import connection
from django.conf import settings
from django.db.utils import OperationalError, ProgrammingError
import threading
import time
from colorama import Fore, Style, init

init(autoreset=True)
logger = logging.getLogger(__name__)

class NeonKeepAliveMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        if getattr(settings, 'NEON_KEEPALIVE_ENABLED', True):
            self._print_banner()
            self._run_initial_connection_check()
            self.ping_thread = threading.Thread(
                target=self._keep_alive,
                daemon=True,
                name="neon_keepalive"
            )
            self.ping_thread.start()
            logger.info("Background connection monitor started")
            print(f"{Fore.GREEN}✓ Background connection monitor active{Style.RESET_ALL}")

    def _print_banner(self):
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"{'Neon PostgreSQL Connection Manager':^50}")
        print(f"{'='*50}{Style.RESET_ALL}\n")

    def _run_initial_connection_check(self):
        try:
            print(f"{Fore.YELLOW}⚡ Attempting initial database connection...{Style.RESET_ALL}")
            logger.info("Initial connection attempt started")
            
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1, current_database(), version()")
                result, db_name, db_version = cursor.fetchone()
                
                if result == 1:
                    msg = f"✓ Connected to {Fore.GREEN}{db_name}{Style.RESET_ALL} ({db_version.split()[0]})"
                    print(msg)
                    logger.info("Database connection established", 
                              extra={'db_name': db_name, 'db_ver': db_version.split()[0]})
                else:
                    raise OperationalError("Unexpected query result")

        except OperationalError as e:
            error_msg = f"{Fore.RED}✗ Connection failed: {e}{Style.RESET_ALL}"
            print(error_msg)
            logger.critical("Connection failed", exc_info=True)
            print(f"\n{Fore.YELLOW}🛠️  Troubleshooting Steps:{Style.RESET_ALL}")
            print(f"1. Verify {Fore.CYAN}DATABASE_URL{Style.RESET_ALL} in settings")
            print(f"2. Check database server status")
            if "SSL" in str(e):
                print(f"3. {Fore.RED}Verify SSL configuration{Style.RESET_ALL}")
            raise

        except ProgrammingError as e:
            error_msg = f"{Fore.RED}✗ Database error: {e}{Style.RESET_ALL}"
            print(error_msg)
            logger.critical("Database configuration error", exc_info=True)
            raise

    def _keep_alive(self):
        interval = getattr(settings, 'NEON_PING_INTERVAL', 200)
        print(f"{Fore.BLUE}🔄 Keep-alive active (every {interval}s){Style.RESET_ALL}")
        logger.info(f"Keep-alive started with {interval} second interval")
        
        while True:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1, current_database(), now() AT TIME ZONE 'UTC'")
                    res = cursor.fetchone()
                    
                    # Console feedback
                    print(f"{Fore.GREEN}✓ {res[2]}: Connection active{Style.RESET_ALL}", end='\r')
                    
                    # File logging (with safe field names)
                    logger.debug("Connection ping", extra={
                        'database': res[1],
                        'timestamp': str(res[2]),
                        'thread_id': threading.get_ident()  # Changed from 'thread'
                    })
                    
            except Exception as e:
                error_msg = f"{Fore.RED}✗ Ping failed: {e}{Style.RESET_ALL}"
                print(error_msg)
                logger.error("Ping failed", exc_info=True,
                           extra={'retry_in': f"{interval} seconds"})
                
            time.sleep(interval)

    def __call__(self, request):
        return self.get_response(request)