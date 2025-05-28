
# user_account/middleware/ping_render.py

import logging
import requests
import threading
import time
from django.conf import settings
from colorama import Fore, Style, init
from urllib.parse import urlparse

init(autoreset=True)
logger = logging.getLogger(__name__)

class RenderKeepAlive:
    def __init__(self, get_response=None):
        self.get_response = get_response
        if getattr(settings, 'RENDER_KEEPALIVE_ENABLED', True):
            self._print_banner()
            self._validate_render_url()
            self.ping_thread = threading.Thread(
                target=self._ping_render,
                daemon=True,
                name="render_keepalive"
            )
            self.ping_thread.start()
            logger.info("Render.com keep-alive monitor started")
            print(f"{Fore.GREEN}✓ Render.com keep-alive active{Style.RESET_ALL}")

    def _print_banner(self):
        print(f"\n{Fore.MAGENTA}{'='*50}")
        print(f"{'Render.com Keep-Alive Manager':^50}")
        print(f"{'='*50}{Style.RESET_ALL}\n")

    def _validate_render_url(self):
        self.render_url = getattr(settings, 'RENDER_HEALTHCHECK_URL', None)
        if not self.render_url:
            raise ValueError("RENDER_HEALTHCHECK_URL not configured in settings")
        
        parsed = urlparse(self.render_url)
        if not all([parsed.scheme, parsed.netloc]):
            raise ValueError(f"Invalid Render URL: {self.render_url}")

    def _ping_render(self):
        interval = 600  # 10 minutes in seconds
        timeout = 30  # Request timeout in seconds
        print(f"{Fore.BLUE}🔄 Render.com ping active (every {interval//60} mins){Style.RESET_ALL}")
        
        while True:
            try:
                start_time = time.time()
                response = requests.get(
                    self.render_url,
                    timeout=timeout,
                    headers={'User-Agent': 'Django-Render-Keepalive/1.0'}
                )
                elapsed = round((time.time() - start_time) * 1000)  # ms
                
                if response.ok:
                    status_msg = f"{Fore.GREEN}✓ {time.ctime()}: Ping successful ({elapsed}ms){Style.RESET_ALL}"
                    print(status_msg)
                    logger.info("Render.com ping succeeded", 
                               extra={
                                   'status_code': response.status_code,
                                   'response_time_ms': elapsed,
                                   'url': self.render_url
                               })
                else:
                    error_msg = f"{Fore.YELLOW}⚠ {response.status_code} Response: {response.text[:100]}{Style.RESET_ALL}"
                    print(error_msg)
                    logger.warning("Render.com ping unexpected response",
                                 extra={
                                     'status_code': response.status_code,
                                     'response': response.text[:500],
                                     'url': self.render_url
                                 })

            except requests.exceptions.RequestException as e:
                error_msg = f"{Fore.RED}✗ Ping failed: {type(e).__name__}{Style.RESET_ALL}"
                print(error_msg)
                logger.error("Render.com ping failed", 
                           exc_info=True,
                           extra={
                               'error_type': type(e).__name__,
                               'url': self.render_url,
                               'retry_in': f"{interval//60} minutes"
                           })

            time.sleep(interval)

    def __call__(self, request):
        if self.get_response:
            return self.get_response(request)
        return None

# For auto-start without middleware (alternative approach)
def start_render_ping():
    """Alternative starter for non-middleware use"""
    if getattr(settings, 'RENDER_KEEPALIVE_ENABLED', True):
        RenderKeepAlive()  # Starts the thread automatically