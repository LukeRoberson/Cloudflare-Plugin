# CloudFlare Plugin

A plugin to manage alerts (webhooks) from the Cloudflare platform.
</br></br>

# Project Organization
## Python Files

| File             | Provided Function                                             |
| ---------------- | ------------------------------------------------------------- |
| main.py          | Entry point to the plugin, load configuration, set up routes  |
| systemlog.py     | Handles sending alerts to the logging service                 |
| event_handler.py | Parses an event and builds fields for logging/alerting        |
</br></br>


## YAML Files

| File        | Provided Function                            |
| ----------- | -------------------------------------------- |
| config.yaml | Configuration for the plugin                 |
| events.yaml | Rules to create and format alerts from event |
</br></br>


# Configuration

## Plugin Configuration

Configuration is handled in config.yaml. The two mandatory sections are:

```yaml
name: "CloudFlare"
chat-id: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

This defines the name of the plugin, and the Teams Chat ID that alerts are sent to.

There are a series of alert types, with actions assigned. This is the action to take, such as sending to Teams, logging to live alerts, etc, when that particular event is received.

```yaml
alert_type:
    web: true
    sql: false
    syslog: false
    teams: true
```

A default set of actions is defined, in case an unknown alert is received:

```yaml
default:
    web: true
    sql: false
    syslog: false
    teams: true
```
</br></br>


## Event Rules

Event rules are used for formatting logs and messages. When an event is received, it is parsed (fields are extracted), and rules are applied to create the log entries and messages.

These rules are stored in events.yaml. There is a rule for each known event type. For example:

```yaml
incident_alert:
  description: "Cloudflare Status: Incident Alert. Cloudflare is experiencing an incident."
  message: "Cloudflare is experiencing an incident: {self.incident_name}\n{self.message}"
```

This is an event type called **incident_alert**. The description is for documentation only, and does not affect the plugin.

The **message** is the formatted output that goes to logs and optionally Teams.

Optionally a **teams** field may be present. This is for a customised Teams message. If this field is not present, the **message** field is used when sending to Teams.


# Webhooks
## Secrets

If a CloudFlare webhook is configured with a secret, it will be sent in plain-text in the **Cf-Webhook-Auth**.

While this is plain-text in the HTTP header, it is encrypted by TLS when it is sent across the internet.
</br></br>


## Message Body Schema

The message body follows this schema:

```json
{
    "name": "Webhook Name",
    "text": "A big text string built on the other fields in the webhook",
    "data": {
        "severity": "INFO",
		<a bunch of alert specific fields>
    },
    "ts": 1749793886,
    "account_id": "1bf413a7-cd88-d3a7-bd63-49d094dfe968",
    "policy_id": "d5a107b0edb64370be11e14b93601314",
    "policy_name": "test",
    "alert_type": "incident_alert"
}
```

Each alert type will have different sub-fields in the **data** field. **severity** is the only common field there.
</br></br>


## Message Headers

Additional headers are included:

```json
{
    "Host": "cloudflare:5000",
    "User-Agent": "Go-http-client/2.0",
    "Accept-Encoding": "gzip, br",
    "Accept": "*/*",
    "Connection": "keep-alive",
    "Content-Type": "application/json",
    "Cf-Ray": "94eeb40eeabaa970-SEA",
    "X-Forwarded-For": "2a06:98c0:360b:1e29:b74d:88ae:1ab2:a67f",
    "Cf-Connecting-Ip": "2a06:98c0:360b:1e29:b74d:88ae:1ab2:a67f",
    "Cdn-Loop": "cloudflare; loops=1",
    "X-Forwarded-Proto": "https",
    "Cf-Webhook-Auth": "plain-text-password",
    "Cf-Ipcountry": "US",
    "Cf-Visitor": "{\"scheme\":\"https\"}",
    "Content-Length": "618"
}
```

</br></br>


## Message Parameters

There are no additional parameters included in the webhook.
</br></br>


## Notification Types

These notifications are configured on the CloudFlare portal under 'notifications'.

| Product              | Alert Type                        | alert_type Field                     |
| -------------------- | --------------------------------- | ------------------------------------ |
| Cloudflare Status    | Incident Alert                    | incident_alert                       |
| Cloudflare Status    | Maintenance Notification          | maintenance_event_notification       |
| Cloudforce One       | Cloudflare Closed Port Scan Alert | closed_port_scan_alert               |
| Cloudforce One       | Cloudflare Open Port Scan Alert   | open_port_scan_alert                 |
| DDoS Protection      | HTTP DDoS Attack Alert            | dos_attack_l7                        |
| Health Checks        | Health Checks status notification | health_check_status_notification     |
| Load Balancing       | Load Balancing Health Alert       | load_balancing_health_alert          |
| Load Balancing       | Pool Enablement                   | load_balancing_pool_enablement_alert |
| Radar                | Radar                             | radar_notification                   |
| Route Leak Detection | Route Leak Detection Alert        | bgp_hijack_notification              |
| SSL/TLS              | Advanced Certificate Alert        | dedicated_ssl_certificate_event_type |
| SSL/TLS              | Universal SSL Alert               | universal_ssl_event_type             |
| Security insights    | New Insight detected              | security_insights_alert              |
| Traffic Monitoring   | Passive Origin Monitoring         | real_origin_monitoring               |
| WAF                  | Security Events Alert             | clickhouse_alert_fw_anomaly          |
</br></br>


The additional data fields for each of these events is listed below.


**Incident Alert**
```json
"data": {
    "affected_components": [
        {
            "id": "kf0ktv29xrfy",
            "name": "Zero Trust"
        }
    ],
    "created_at": "2022-10-27T06:00:22Z",
    "id": "zks4n7lyhzmv",
    "incident_created_at": "2022-10-27T06:00:22Z",
    "incident_id": "n7058grjk59r",
    "incident_impact": "INCIDENT_IMPACT_MINOR",
    "incident_name": "(TEST ALERT) Regional degraded connectivity for Secure Web Gateway",
    "incident_status": "INCIDENT_STATUS_MONITORING",
    "message": "(TEST MESSAGE) A fix has been implemented and we are monitoring the results.",
    "status": "INCIDENT_STATUS_MONITORING"
},
```


**maintenance_event_notification**
```json
"data": {
    "airport_code": "LHR",
    "event_type": "MAINTENANCE_EVENT_TYPE_CHANGED",
    "maintenance_id": "11111111111",
    "scheduled_end": "2022-10-27T06:00:22Z",
    "scheduled_start": "2022-10-27T06:00:22Z",
},
```


**closed_port_scan_alert**
```json
"data": {
    "account_name": "account-name",
    "account_tag": "aBcD1234efgh567i890j1kl234567m89",
    "ports": [
        {
            "ip": "127.0.0.1",
            "number": 8080,
            "status": "CLOSED"
        }
    ],
    "scanned_at": "2022-10-27T06:00:22Z",
},
```


**open_port_scan_alert**
```json
"data": {
    "account_name": "account-name",
    "account_tag": "aBcD1234efgh567i890j1kl234567m89",
    "ports": [
        {
            "ip": "127.0.0.1",
            "number": 8080,
            "status": "OPENED"
        }
    ],
    "scanned_at": "2022-10-27T06:00:22Z",
},
```


**dos_attack_l7**
```json
"data": {
    "account_name": "account-name",
    "account_tag": "aBcD1234efgh567i890j1kl234567m89",
    "action": "fake-action",
    "attack_id": "aBcD1234efgh567i890j1kl234567m80",
    "attack_type": "http-fake-browser",
    "dashboard_link": "dash.cloudflare.com/aBcD1234efgh567i890j1kl234567m89",
    "max_rate": "800.00 rps",
    "mitigation": "managed-challenge",
    "requests_per_second": "800",
    "rule_description": "fake-description",
    "rule_id": "aBcD1234efgh567i890j1kl234567m80",
    "rule_link": "rule-1234",
    "ruleset_id": "aBcD1234efgh567i890j1kl234567m80",
    "ruleset_override_id": "aBcD1234efgh567i890j1kl234567m80",
    "start_time": "2022-10-27T06:00:22Z",
    "target_hostname": "fake-zone-name",
    "target_id": "11111111111",
    "target_zone_name": "fake-zone-name",
    "zone_plan": "ent"
},
```


**health_check_status_notification**
```json
"data": {
    "actual_code": 404,
    "expected_codes": "[2xx 302]",
    "health_check_id": "11111111111",
    "name": "origin-abcd",
    "preview": true,
    "reason": "No failures",
    "status": "Healthy",
    "time": "1970-01-01 00:00:00 +0000 UTC"
},
```



**load_balancing_health_alert**
```json
"data": {
    "alert_name": "load_balancing_health_alert",
    "event_source": "origin",
    "load_balancers": "test-lb",
    "new_health": "Healthy",
    "origin_failure_reason": "No failures",
    "origin_name": "west-usa-origin",
    "pool_id": "11111111111",
    "pool_name": "pool-name",
    "regions": "enam",
    "timestamp": "2022-10-27T06:00:22Z"
},
```


**load_balancing_pool_enablement_alert**
```json
"data": {
    "alert_name": "Pool Enablement",
    "auth_info": {
        "account_name": "account-name",
        "account_tag": "aBcD1234efgh567i890j1kl234567m89",
        "actor_email": "email@example.com"
    },
    "enabled": true,
    "pool_id": "11111111111",
    "pool_name": "pool-name",
    "updated_at": "2022-10-27T06:00:22Z"
},
```


**radar_notification**
```json
"data": {
    "affected_asns": [
        "174",
        "17072",
        "32098"
    ],
    "affected_locations": [
        "PT"
    ],
    "bgp_leak": {
        "asn_by": {
            "code": "17072",
            "name": "Total Play"
        },
        "asn_from": {
            "code": "174",
            "name": "Cogent"
        },
        "asn_to": {
            "code": "32098",
            "name": "Transtelco"
        },
        "origin_count": 1,
        "peer_count": 11,
        "prefix_count": 1
    },
    "event_end_time": "2022-10-27T06:00:22Z",
    "event_id": "212418",
    "event_link": "https://radar.cloudflare.com/routing/anomalies/leak-212418",
    "event_start_time": "2022-10-27T06:00:22Z",
    "event_title": "BGP Route Leak - AS212418",
    "event_type": "BGP_LEAK",
    "event_window_end_time": "2023-09-05",
    "event_window_start_time": "2023-09-05",
},
```


**bgp_hijack_notification**
```json
"data": {
    "ASNs_seen": [
        "100",
        "200"
    ],
    "account_name": "account-name",
    "additional_info": "fake-additional",
    "alert_priority_level": "CRITICAL",
    "alert_start_time": "2022-10-27T06:00:22Z",
    "alert_title": "fake-title",
    "alert_type": "bgp_hijack_notification",
    "dashboard_link": "dash.cloudflare.com/aBcD1234efgh567i890j1kl234567m89",
    "hijack_as": "hijack-as",
    "prefix_configured": "configured-prefix",
    "prefix_hijacked": "hijacked-prefix",
},
```



**dedicated_ssl_certificate_event_type**
```json
"data": {
    "data": {
        "custom_csr_id": "",
        "expires_on": null,
        "hosts": [
        ],
        "id": "11111111111",
        "issuer": "",
        "method": "txt",
        "serial_number": "",
        "settings": null,
        "signature": "",
        "status": "",
        "type": "",
        "uploaded_on": null,
        "validation_errors": [
        ],
        "validation_records": [
            {
                "cname": "",
                "cname_target": "",
                "emails": [
                ],
                "http_body": "",
                "http_url": "",
                "txt_name": "_acme-challenge.example.com",
                "txt_value": "11111111111"
            }
        ]
    },
    "metadata": {
        "account": null,
        "event": {
            "created_at": null,
            "id": "",
            "type": "ssl.dedicated_certificate.validation.failed"
        },
        "zone": {
            "id": "11111111111"
        }
    },
},
```



**universal_ssl_event_type**
```json
"data": {
    "data": {
        "custom_csr_id": "",
        "expires_on": null,
        "hosts": [
        ],
        "id": "11111111111",
        "issuer": "",
        "method": "txt",
        "serial_number": "",
        "settings": null,
        "signature": "",
        "status": "",
        "type": "",
        "uploaded_on": null,
        "validation_errors": [
        ],
        "validation_records": [
            {
                "cname": "",
                "cname_target": "",
                "emails": [
                ],
                "http_body": "",
                "http_url": "",
                "txt_name": "_acme-challenge.example.com",
                "txt_value": "11111111111"
            }
        ]
    },
    "metadata": {
        "account": null,
        "event": {
            "created_at": null,
            "id": "",
            "type": "ssl.certificate.validation.failed"
        },
        "zone": {
            "id": "11111111111"
        }
    },
},
```


**security_insights_alert**
```json
'data': {
    "account_name": "account-name",
    "account_tag": "aBcD1234efgh567i890j1kl234567m89",
    "insight_class": "Insight Class",
    "subject": "Subject",
    "timestamp": "2025-06-13T06:13:37.721192654Z"
}, 
```


**real_origin_monitoring**
```json
"data": {
    "account_tag": "aBcD1234efgh567i890j1kl234567m89",
    "unreachable_zones": [
        {
            "host": "",
            "zone_name": "zone-name"
        }
    ]
},
```


**clickhouse_alert_fw_anomaly**
```json
"data": {
    "account_name": "account-name",
    "actions": "undefined",
    "alert_start_time": "2022-10-27T06:00:22Z",
    "dashboard_link": "dash.cloudflare.com/aBcD1234efgh567i890j1kl234567m89/firewallftw",
    "events_count": "44",
    "services": "1234",
    "zone_name": "zone-name",
    "zone_tag": "zYxW9876vUtS5432zYxW9876vUtS5432",
    "zones": "1234"
},
```
