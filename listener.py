#!/usr/bin/env python
import base64
import datetime
import logging
import os
import pathlib
import signal
import socket
import subprocess
import time
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http import HTTPStatus
from threading import Thread
from urllib.parse import urlparse
import json
import io
from types import SimpleNamespace

import requests
from lxml import etree
from zeep import Client
from zeep.wsse.username import UsernameToken

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

logger = logging.getLogger("DoorbellListener")
formatter = logging.Formatter(
    "%(asctime)s.%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)3d] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

already_seen_events = set()


class ONVIFEventRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/test/visitor":
            self.handle_visitor_event(datetime.datetime.now())
            self.send_response(HTTPStatus.OK)
            self.wfile.write("".encode("utf-8"))

    def do_POST(self):
        if "application/soap+xml" in self.headers.get("Content-Type"):
            self.handle_soap_POST()
            self.send_response(HTTPStatus.OK)

    def handle_visitor_event(self, timestamp):
        # This event is sent when the doorbell is pressed.
        if (datetime.datetime.utcnow() - timestamp).total_seconds() <= 5:
            image_data = take_snapshot(
                ONVIF_SERVICE_URL,
                username=config.username,
                password=config.password,
                outfile=config.snapshot_path,
            )

            am_args = [
                "am",
                "broadcast",
                "--user",
                "0",
                "-a",
                "net.dinglish.tasker.DoorbellVisitor",
            ]
            try:
                subprocess.run(am_args, check=True, capture_output=True)
            except FileNotFoundError:
                logger.warning(
                    "Tried to broadcast an intent, but couldn't find a executable named 'am' on this device."
                )
            except subprocess.CalledProcessError as e:
                logger.warning(
                    "Tried to broadcast an intent, but am did not run sucessfully."
                )

    def handle_motion_event(self, timestamp):
        pass

    def handle_soap_POST(self):
        post_body = self.rfile.read(int(self.headers.get("Content-Length")))
        tree = etree.fromstring(post_body)

        if b"NotificationConsumer" in post_body:
            for nm in tree.xpath(".//*[local-name() = 'NotificationMessage']"):
                topic = nm.find("{http://docs.oasis-open.org/wsn/b-2}Topic")
                messages = nm.xpath(".//*[name() = 'tt:Message']")
                for message in messages:
                    message_utc_time = message.get("UtcTime", "1970-01-01T00:00Z")
                    message_time = datetime.datetime.fromisoformat(message_utc_time)
                    message_key = f"{message_utc_time}:{topic.text}"
                    if message_time.year == 1970 or message_key in already_seen_events:
                        continue

                    already_seen_events.add(message_key)

                    source = message.find(
                        "{http://www.onvif.org/ver10/schema}Source"
                    ).find("{http://www.onvif.org/ver10/schema}SimpleItem")
                    state = message.find(
                        "{http://www.onvif.org/ver10/schema}Data"
                    ).find("{http://www.onvif.org/ver10/schema}SimpleItem")

                    source_value = source.get("Value")
                    state_value = state.get("Value")

                    local_time = message_time.astimezone()
                    logger.info(
                        f"{local_time}:{topic.text} Source:{source_value} State:{state_value}"
                    )
                    if topic.text.endswith("Visitor"):
                        self.handle_visitor_event(message_time.replace(tzinfo=None))
                    if topic.text.endswith("MotionAlarm"):
                        self.handle_motion_event(message_time.replace(tzinfo=None))
        else:
            logger.info(etree.tounicode(etree.fromstring(post_body), pretty_print=True))


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(("255.255.255.255", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def run_listen_server(listen_port=0):
    global httpd, server_thread
    httpd = ThreadingHTTPServer(("", listen_port), ONVIFEventRequestHandler)
    _, listen_port = httpd.socket.getsockname()

    server_thread = Thread(target=httpd.serve_forever, name="http_server", daemon=True)
    server_thread.start()

    local_ip = get_local_ip()
    listener_address = f"http://{local_ip}:{listen_port}"
    logger.info(f"Listening for events at {listener_address}.")

    return listener_address


def take_snapshot(onvif_service_url, username=None, password=None, outfile=None):
    logger.info("Taking snapshot from camera.")
    media_client = Client(
        pathlib.Path(WSDL_LOCATION).joinpath("wsdl/media.wsdl").as_posix(),
        wsse=UsernameToken(username, password, use_digest=True),
    )
    media_client_service = media_client.create_service(
        "{http://www.onvif.org/ver10/media/wsdl}MediaBinding", onvif_service_url
    )

    uri = media_client_service.GetSnapshotUri(
        ProfileToken=media_client_service.GetProfiles()[0].token
    ).Uri

    # Seems like this method should return https, but it doesn't?
    parsed_uri = urlparse(uri)
    parsed_uri = parsed_uri._replace(
        scheme="https", netloc=parsed_uri.netloc.replace(":80", ":443")
    ).geturl()

    response = requests.get(
        parsed_uri,
        auth=requests.auth.HTTPDigestAuth(username, password),
        verify=False,
        stream=True,
    )

    if outfile is not None:
        with open(outfile, "wb") as f:
            for chunk in response:
                f.write(chunk)
    else:
        outfile = io.BytesIO()
        for chunk in response:
            outfile.write(chunk)

        return outfile.getvalue()


def subscribe(
    onvif_service_url,
    username=None,
    password=None,
    subscription_duration="0H0M10S",
    listen_port=0,
):
    try:
        CONSUMER_ADDRESS = run_listen_server(listen_port=listen_port)
    except Exception as e:
        raise
    else:
        while True:
            event_client = Client(
                pathlib.Path(WSDL_LOCATION).joinpath("wsdl/events.wsdl").as_posix(),
                wsse=UsernameToken(username, password, use_digest=True),
            )
            notification_producer_service = event_client.create_service(
                "{http://www.onvif.org/ver10/events/wsdl}NotificationProducerBinding",
                onvif_service_url,
            )

            logger.info(
                f"Requesting event subscription for {subscription_duration} from ONVIF service at {onvif_service_url}."
            )
            response = notification_producer_service.Subscribe(
                ConsumerReference={"Address": f"{CONSUMER_ADDRESS}"},
                InitialTerminationTime=f"PT{subscription_duration}",
            )

            if response:
                logger.info(
                    f"Got response from ONVIF service. Subscription will expire at {response.TerminationTime.astimezone()}."
                )
            sleep_seconds = (
                response.TerminationTime.replace(tzinfo=None)
                - datetime.datetime.utcnow()
            )
            logger.info(
                f"Sleeping for {sleep_seconds.total_seconds()} seconds, until {(datetime.datetime.utcnow() + sleep_seconds).astimezone()}"
            )
            time.sleep(sleep_seconds.total_seconds())


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="""Subscribes to, then listens for events produced by an ONVIF-compliant camera."""
    )

    parser.add_argument(
        "--config-file",
        required=False,
        default="listener.cfg.json",
    )
    args = parser.parse_args()

    try:
        with open(args.config_file, "rb") as f:
            config = json.load(f, object_hook=lambda d: SimpleNamespace(**d))
    except FileNotFoundError:
        exit(f"Couldn't find configuration file: {args.config_file}")

    WSDL_LOCATION = os.path.dirname(__file__)
    ONVIF_SERVICE_URL = (
        f"http://{config.camera_ip}:{config.camera_onvif_port}/onvif/device_service"
    )

    httpd = server_thread = None

    def handle_exit():
        logger.info("Shutting down listen server.")
        if httpd:
            httpd.shutdown()
        if server_thread:
            server_thread.join()

    signal.signal(signal.SIGTERM, handle_exit)

    try:
        subscribe(
            ONVIF_SERVICE_URL,
            username=config.username,
            password=config.password,
            listen_port=getattr(config, "listen_port", 9090),
            subscription_duration=config.subscription_duration,
        )
    except (KeyboardInterrupt, SystemExit):
        handle_exit()
        raise
