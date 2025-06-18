"""
Module: event_handler.py

Handle webhook events from Cloudflare and process them accordingly.

Classes:
    EventHandler: Class to handle webhook events from Cloudflare.
        It validates the webhook, extracts common and specific fields,
        and processes the event to send logs to the logging service.

Dependencies:
    requests: For making HTTP requests to the logging service and
        fetching plugin configuration.
    logging: For logging errors and debug messages.
    yaml: For loading event handling configuration from a YAML file.
    flask: For accessing the current application context.
"""

# Standard library imports
import requests
import logging
import yaml
from flask import current_app


PLUGINS_URL = "http://web-interface:5100/api/plugins"


# Get event handling configuration from the YAML file
with open("events.yaml", "r") as file:
    EVENTS = yaml.safe_load(file)


class EventHandler:
    """
    EventHandler class to handle webhook events from Cloudflare.

    _common_fields: Extracts common fields from the event data.
    _data_fields: Extracts specific fields from the event data based
        on the alert type.

    Args:
        config (dict): Configuration dictionary containing necessary settings.
    """

    def __init__(
        self,
        config
    ) -> None:
        """
        Initialize the EventHandler with the provided configuration.

        Args:
            config (dict):
                Configuration dictionary containing necessary settings.

        Returns:
            None
        """

        self.config = config

    def __enter__(
        self
    ) -> 'EventHandler':
        """
        Enter the runtime context related to this object.

        Args:
            None

        Returns:
            EventHandler: The current instance of EventHandler.
        """

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback
    ) -> None:
        """
        Exit the runtime context related to this object.

        Args:
            exc_type: The exception type.
            exc_value: The exception value.
            traceback: The traceback object.

        Returns:
            None
        """

        # Handle any cleanup if necessary
        if exc_type is not None:
            # Log the exception or handle it as needed
            print(f"Exception occurred: {exc_value}")

    def _validate(
        self,
        headers: dict,
    ) -> bool:
        """
        Validate the webhook using the Cf-Webhook-Auth header.
            This is string in plain-text that just needs to match the
                configured secret.
            The core service has the secret stored in the plugin config.

        Args:
            None

        Returns:
            bool: True if the webhook is valid, False otherwise.
        """

        # Check that there is an auth header
        auth_header = headers.get('Cf-Webhook-Auth', None)
        if auth_header is None:
            print("No auth header found in the request.")
            return False

        # Fetch the secret from the plugin config
        try:
            secret_resp = requests.get(
                PLUGINS_URL,
                headers={'X-Plugin-Name': self.config['name']}
            )
            secret_resp.raise_for_status()
            secret = secret_resp.json()['plugin']['webhook']['secret']

        except Exception as e:
            logging.error(f"Error fetching webhook secret: {e}")
            return False

        if auth_header == secret:
            logging.debug("Webhook validation successful.")
            return True

        else:
            logging.error(
                "Webhook validation failed. Auth header does not match."
            )
            return False

    def _common_fields(
        self,
        event: dict,
    ) -> bool:
        """
        Extract common fields from the event data and store them.
            These fields are available in all webhook events.

        Args:
            event (dict): The event data received from Cloudflare.

        Returns:
            bool: True if all required fields are present, False otherwise.
        """

        # The name of the webhook, as defined in the Cloudflare dashboard
        self.webhook_name = self.event.get('name', None)

        # The notification policy name, as defined in the Cloudflare dashboard
        self.policy_name = self.event.get('policy_name', None)

        # A large string, made up of the event data (can get from other fields)
        self.text = self.event.get('text', None)

        # The timestamp of the event in epoch format
        self.ts = self.event.get('ts', None)

        # The name of the item that triggered the alert (eg, 'incident_alert')
        self.alert_type = self.event.get('alert_type', None)

        # Check that all required fields are present
        required_fields = [
            self.webhook_name,
            self.policy_name,
            self.text,
            self.ts,
            self.alert_type
        ]

        if any(field is None for field in required_fields):
            return False

        return True

    def _data_fields(
        self,
    ) -> bool:
        """
        Extract sub-fields from the data field in the event data.
            These fields are specific to the type of alert and may vary.

        Args:
            None

        Returns:
            bool: True if all required fields are present, False otherwise.
        """

        if self.alert_type == "incident_alert":
            self.affected_components = self.event.get('data', {}).get(
                'affected_components', None
            )
            self.created_at = self.event.get('data', {}).get(
                'created_at', None
            )
            self.id = self.event.get('data', {}).get(
                'id', None
            )
            self.incident_name = self.event.get('data', {}).get(
                'incident_name', None
            )
            self.incident_created_at = self.event.get('data', {}).get(
                'incident_created_at', None
            )
            self.incident_id = self.event.get('data', {}).get(
                'incident_id', None
            )
            self.incident_impact = self.event.get('data', {}).get(
                'incident_impact', None
            )
            self.incident_status = self.event.get('data', {}).get(
                'incident_status', None
            )
            self.message = self.event.get('data', {}).get(
                'message', None
            )
            self.status = self.event.get('data', {}).get(
                'status', None
            )

        elif self.alert_type == "maintenance_event_notification":
            self.airport_code = self.event.get('data', {}).get(
                'airport_code', None
            )
            self.event_type = self.event.get('data', {}).get(
                'event_type', None
            )
            self.maintenance_id = self.event.get('data', {}).get(
                'maintenance_id', None
            )
            self.scheduled_start = self.event.get('data', {}).get(
                'scheduled_start', None
            )
            self.scheduled_end = self.event.get('data', {}).get(
                'scheduled_end', None
            )

        elif self.alert_type == "closed_port_scan_alert":
            self.account_name = self.event.get('data', {}).get(
                'account_name', None
            )
            self.account_tag = self.event.get('data', {}).get(
                'account_tag', None
            )
            self.ports = self.event.get('data', {}).get(
                'ports', None
            )
            self.scanned_at = self.event.get('data', {}).get(
                'scanned_at', None
            )

        elif self.alert_type == "open_port_scan_alert":
            self.account_name = self.event.get('data', {}).get(
                'account_name', None
            )
            self.account_tag = self.event.get('data', {}).get(
                'account_tag', None
            )
            self.ports = self.event.get('data', {}).get(
                'ports', None
            )
            self.scanned_at = self.event.get('data', {}).get(
                'scanned_at', None
            )

        elif self.alert_type == "dos_attack_l7":
            self.account_name = self.event.get('data', {}).get(
                'account_name', None
            )
            self.account_tag = self.event.get('data', {}).get(
                'account_tag', None
            )
            self.action = self.event.get('data', {}).get(
                'action', None
            )
            self.attack_id = self.event.get('data', {}).get(
                'attack_id', None
            )
            self.attack_type = self.event.get('data', {}).get(
                'attack_type', None
            )
            self.dashboard_link = self.event.get('data', {}).get(
                'dashboard_link', None
            )
            self.max_rate = self.event.get('data', {}).get(
                'max_rate', None
            )
            self.mitigation = self.event.get('data', {}).get(
                'mitigation', None
            )
            self.requests_per_second = self.event.get('data', {}).get(
                'requests_per_second', None
            )
            self.rule_description = self.event.get('data', {}).get(
                'rule_description', None
            )
            self.rule_id = self.event.get('data', {}).get(
                'rule_id', None
            )
            self.rule_link = self.event.get('data', {}).get(
                'rule_link', None
            )
            self.ruleset_id = self.event.get('data', {}).get(
                'ruleset_id', None
            )
            self.ruleset_override_id = self.event.get('data', {}).get(
                'ruleset_override_id', None
            )
            self.start_time = self.event.get('data', {}).get(
                'start_time', None
            )
            self.target_hostname = self.event.get('data', {}).get(
                'target_hostname', None
            )
            self.target_id = self.event.get('data', {}).get(
                'target_id', None
            )
            self.target_zone_name = self.event.get('data', {}).get(
                'target_zone_name', None
            )
            self.zone_plan = self.event.get('data', {}).get(
                'zone_plan', None
            )

        elif self.alert_type == "health_check_status_notification":
            self.actual_code = self.event.get('data', {}).get(
                'actual_code', None
            )
            self.expected_code = self.event.get('data', {}).get(
                'expected_code', None
            )
            self.health_check_id = self.event.get('data', {}).get(
                'health_check_id', None
            )
            self.name = self.event.get('data', {}).get(
                'name', None
            )
            self.preview = self.event.get('data', {}).get(
                'preview', None
            )
            self.reason = self.event.get('data', {}).get(
                'reason', None
            )
            self.status = self.event.get('data', {}).get(
                'status', None
            )
            self.time = self.event.get('data', {}).get(
                'time', None
            )

        elif self.alert_type == "load_balancing_health_alert":
            self.alert_name = self.event.get('data', {}).get(
                'alert_name', None
            )
            self.event_source = self.event.get('data', {}).get(
                'event_source', None
            )
            self.load_balancers = self.event.get('data', {}).get(
                'load_balancers', None
            )
            self.new_health = self.event.get('data', {}).get(
                'new_health', None
            )
            self.origin_failure_reason = self.event.get('data', {}).get(
                'origin_failure_reason', None
            )
            self.origin_name = self.event.get('data', {}).get(
                'origin_name', None
            )
            self.pool_id = self.event.get('data', {}).get(
                'pool_id', None
            )
            self.pool_name = self.event.get('data', {}).get(
                'pool_name', None
            )
            self.regions = self.event.get('data', {}).get(
                'regions', None
            )
            self.timestamp = self.event.get('data', {}).get(
                'timestamp', None
            )

        elif self.alert_type == "load_balancing_pool_enablement_alert":
            self.alert_name = self.event.get('data', {}).get(
                'alert_name', None
            )
            self.auth_info = self.event.get('data', {}).get(
                'auth_info', None
            )
            self.enabled = self.event.get('data', {}).get(
                'enabled', None
            )
            self.pool_id = self.event.get('data', {}).get(
                'pool_id', None
            )
            self.pool_name = self.event.get('data', {}).get(
                'pool_name', None
            )
            self.updated_at = self.event.get('data', {}).get(
                'updated_at', None
            )

        elif self.alert_type == "radar_notification":
            self.affected_asns = self.event.get('data', {}).get(
                'affected_asns', None
            )
            self.affected_locations = self.event.get('data', {}).get(
                'affected_locations', None
            )
            self.bgp_leak = self.event.get('data', {}).get(
                'bgp_leak', None
            )
            self.event_end_time = self.event.get('data', {}).get(
                'event_end_time', None
            )
            self.event_id = self.event.get('data', {}).get(
                'event_id', None
            )
            self.event_link = self.event.get('data', {}).get(
                'event_link', None
            )
            self.event_start_time = self.event.get('data', {}).get(
                'event_start_time', None
            )
            self.event_title = self.event.get('data', {}).get(
                'event_title', None
            )
            self.event_type = self.event.get('data', {}).get(
                'event_type', None
            )
            self.event_window_end_time = self.event.get('data', {}).get(
                'event_window_end_time', None
            )
            self.event_window_start_time = self.event.get('data', {}).get(
                'event_window_start_time', None
            )

        elif self.alert_type == "bgp_hijack_notification":
            self.ASNs_seen = self.event.get('data', {}).get(
                'ASNs_seen', None
            )
            self.account_name = self.event.get('data', {}).get(
                'account_name', None
            )
            self.additional_info = self.event.get('data', {}).get(
                'additional_info', None
            )
            self.alert_priority_level = self.event.get('data', {}).get(
                'alert_priority_level', None
            )
            self.alert_start_time = self.event.get('data', {}).get(
                'alert_start_time', None
            )
            self.alert_title = self.event.get('data', {}).get(
                'alert_title', None
            )
            self.alert_type = self.event.get('data', {}).get(
                'alert_type', None
            )
            self.dashboard_link = self.event.get('data', {}).get(
                'dashboard_link', None
            )
            self.hijack_as = self.event.get('data', {}).get(
                'hijack_as', None
            )
            self.prefix_configured = self.event.get('data', {}).get(
                'prefix_configured', None
            )
            self.prefix_hijacked = self.event.get('data', {}).get(
                'prefix_hijacked', None
            )

        elif self.alert_type == "dedicated_ssl_certificate_event_type":
            self.data = self.event.get('data', {}).get(
                'data', None
            )
            self.metadata = self.event.get('data', {}).get(
                'metadata', None
            )

        elif self.alert_type == "universal_ssl_event_type":
            self.data = self.event.get('data', {}).get(
                'data', None
            )
            self.metadata = self.event.get('data', {}).get(
                'metadata', None
            )

        elif self.alert_type == "security_insights_alert":
            self.account_name = self.event.get('data', {}).get(
                'account_name', None
            )
            self.account_tag = self.event.get('data', {}).get(
                'account_tag', None
            )
            self.insight_class = self.event.get('data', {}).get(
                'insight_class', None
            )
            self.subject = self.event.get('data', {}).get(
                'subject', None
            )
            self.timestamp = self.event.get('data', {}).get(
                'timestamp', None
            )

        elif self.alert_type == "real_origin_monitoring":
            self.account_tag = self.event.get('data', {}).get(
                'account_tag', None
            )
            self.unreachable_zones = self.event.get('data', {}).get(
                'unreachable_zones', None
            )

        elif self.alert_type == "clickhouse_alert_fw_anomaly":
            self.account_name = self.event.get('data', {}).get(
                'account_name', None
            )
            self.actions = self.event.get('data', {}).get(
                'actions', None
            )
            self.alert_start_time = self.event.get('data', {}).get(
                'alert_start_time', None
            )
            self.dashboard_link = self.event.get('data', {}).get(
                'dashboard_link', None
            )
            self.event_count = self.event.get('data', {}).get(
                'event_count', None
            )
            self.services = self.event.get('data', {}).get(
                'services', None
            )
            self.zone_name = self.event.get('data', {}).get(
                'zone_name', None
            )
            self.zone_tag = self.event.get('data', {}).get(
                'zone_tag', None
            )
            self.zones = self.event.get('data', {}).get(
                'zones', None
            )

        else:
            logging.error(
                f"Unhandled alert type: {self.alert_type}. "
                f"Cannot extract data fields.\n{self.event}"
            )
            return False

        return True

    def _parse_body(
        self,
    ) -> dict:
        """
        Work through the fields in the request body and build a message to
            send to the logging service.

        Args:
            None

        Returns:
            dict: A dictionary containing the log message and Teams message.
        """

        message = ""

        # Get the handler for the alert type
        handler = EVENTS.get(self.alert_type, None)
        if handler is None:
            logging.error(
                f"Unhandled alert type: {self.alert_type}. "
                "Cannot process event."
            )
            message = f"Unhandled CloudFlare event: {self.event}:\n"

        else:
            try:
                # Get the formatted message
                message = handler.get(
                    "message",
                    self.event
                ).format(self=self)

                # If there is a Teams message (optional), get it too
                self.teams_msg = handler.get("teams", None)
                if self.teams_msg:
                    self.teams_msg = self.teams_msg.format(self=self)

            except Exception as e:
                logging.error(
                    f"Error formatting event message for {self.event}:\n{e}"
                )
                message = "No message included"
                self.teams_msg = str(self.event)
                self.severity = "warning"

        log = {
            "source": "CloudFlare",
            "log": {
                "group": self.name,
                "category": self.alert_type,
                "alert": self.status,
                "severity": self.severity,
                "timestamp": self.ts,
                "message": message,
            },
            "teams": {
                "destination": self.config['chat-id'],
                "message": message,
            }
        }

        return log

    def process_event(
        self,
        event: dict,
        headers: dict,
    ) -> None:
        """
        Basic processing of a webhook event from Cloudflare.
            Extracts fields from the event and stores them in the instance.

        Args:
            event (dict): The event data received from Cloudflare.

        Returns:
            None
        """

        # Validate the webhook
        if not self._validate(headers=headers):
            logging.error(
                "Webhook validation failed. Event processing aborted."
            )
            return

        # Store the event data
        self.event = event

        # Extract common fields
        result = self._common_fields(event)
        if result is False:
            logging.error(
                """
                Missing required fields in the event data.
                Event processing aborted.
                """
            )
            return

        # Extract specific data fields based on the alert type
        result = self._data_fields()

        # The name of the item that triggered the alert (eg, a failed service)
        self.name = event.get('data', {}).get('name', None)

        # The reason for the alert, sich as "service down" or "no failures"
        self.reason = event.get('data', {}).get('reason', None)

        # The severity of the alert, such as "INFO"
        self.severity = event.get('data', {}).get('severity', None)

        # The status of the alert, such as "Healthy"
        self.status = event.get('data', {}).get('status', None)

        # Parse the body and build a message to send to the logging service
        log = self._parse_body()

        # Get the actions to perform
        if self.alert_type in self.config:
            actions = self.config[self.alert_type]
        else:
            actions = self.config["default"]

        # Convert this to a list of actions
        action_list = []
        action_list = [
            k for k in ("web", "teams", "syslog", "sql") if actions.get(k)
        ]
        log["destination"] = action_list

        # If no actions are specified, do nothing
        if not action_list:
            return

        # Check if there is a custom chat ID for Teams messages
        chat_ids = current_app.config.get('PLUGIN_CONFIG', {}).get('chats', {})
        teams_chat = chat_ids.get('default', None)
        if 'chat' in actions:
            teams_chat = chat_ids.get(
                actions['chat'], None
            )

        # Log to logging service
        system_log = current_app.config['SYSTEM_LOG']
        system_log.log(
            message=log['log']['message'],
            destination=log['destination'],
            group=log['log']['group'],
            category=log['log']['category'],
            alert=log['log']['alert'],
            severity=log['log']['severity'],
            teams_msg=log['teams']['message'],
            chat_id=teams_chat,
        )
