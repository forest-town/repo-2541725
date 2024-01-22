=============
Release Notes
=============

.. _Release Notes_7.50.3:

7.50.3 / 6.50.3
======

.. _Release Notes_7.50.3_Prelude:

Prelude
-------

Release on: 2024-01-11


.. _Release Notes_7.50.3_Bug Fixes:

Bug Fixes
---------

- Fix incorrect metadata about system-probe being sent to Inventory and Fleet Automation products.


.. _Release Notes_7.50.2:

7.50.2 / 6.50.2
======

.. _Release Notes_7.50.2_Prelude:

Prelude
-------

Release on: 2024-01-04

- Please refer to the `7.50.2 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7502>`_ for the list of changes on the Core Checks


.. _Release Notes_7.50.2_Enhancement Notes:

Enhancement Notes
-----------------

- Agents are now built with Go ``1.20.12``.


.. _Release Notes_7.50.2_Bug Fixes:

Bug Fixes
---------

- The CWS configuration parameter to enable anomaly detection is now working and taken
  into account by the Agent.

- Fix issue introduced in 7.47 that allowed all users to start/stop the
  Windows Datadog Agent services. The Windows installer now, as in versions
  before 7.47, grants this permission explicitly to ddagentuser.


.. _Release Notes_7.50.1:

7.50.1 / 6.50.1
======

.. _Release Notes_7.50.1_Prelude:

Prelude
-------

Release on: 2023-12-21

Bug Fixes
---------

- Fixes a bug introduced in `7.50.0` preventing `DD_TAGS` to be added to `kubernetes_state.*` metrics.


.. _Release Notes_7.50.0:

7.50.0 / 6.50.0
======

.. _Release Notes_7.50.0_Prelude:

Prelude
-------

Release on: 2023-12-18

- Please refer to the `7.50.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7500>`_ for the list of changes on the Core Checks


.. _Release Notes_7.50.0_Upgrade Notes:

Upgrade Notes
-------------

- The `win32_event_log check <https://docs.datadoghq.com/integrations/win32_event_log/?tab=events>`_
  has moved from Python `(integrations-core#16108) <https://github.com/DataDog/integrations-core/pull/16108>`_
  to Go `(#20701 <https://github.com/DataDog/datadog-agent/pull/20701>)`_.
  All ``legacy_mode: false`` configuration options are backwards compatible except for some regular expressions
  used in the ``included_messages`` and ``excluded_messages`` options.
  For example, Go regular expressions do not support lookahead or lookbehind assertions. If you do not
  use these options, then no configuration changes are necessary.
  See the `Python regular expression docs <https://docs.python.org/3/library/re.html>`_ and the
  `Go regular expression docs <https://github.com/google/re2/wiki/Syntax>`_ for more information on
  the supported regular expression syntax.
  Set ``legacy_mode_v2: true`` to revert to the Python implementation of the check. The Python implementation
  may be removed in a future version of the Agent.


.. _Release Notes_7.50.0_New Features:

New Features
------------

- The orchestrator check is moving from the Process Agent to the Node Agent. In the next release, this new check will replace the current pod check in the Process Agent. You can start using this new check now by manually setting the environment variable ``DD_ORCHESTRATOR_EXPLORER_RUN_ON_NODE_AGENT`` to ``true``.

- Adds the following CPU manager metrics to the kubelet core check: `kubernetes_core.kubelet.cpu_manager.pinning_errors_total`, `kubernetes_core.kubelet.cpu_manager.pinning_requests_total`.

- Add a diagnosis for connecting to the agent logs endpoints. This is accessible through the ``agent diagnose`` command.

- Add FIPS mode support for Network Device Monitoring products

- Added support for collecting Cloud Foundry container names without the Cluster Agent.

- The Kubernetes State Metrics Core check now collects `kubernetes_state.ingress.tls`.

- APM: Added a new endpoint tracer_flare/v1/. This endpoint acts as a
  proxy to forward HTTP POST request from tracers to the serverless_flare
  endpoint, allowing tracer flares to be triggered via remote config, improving
  the support experience by automating the collection of logs.

- CWS: Ability to send a signal to a process when a rule was triggered.
  CWS: Add Kubernetes user session context to events, in particular the username, UID and groups of the user that ran the commands remotely.

- Enable container image collection by default.

- Enable container lifecycle events collection by default.
  This feature helps stopped containers to be cleaned from Datadog faster.

- [netflow] Allow collecting configurable fields for Netflow V9/IPFIX

- Add support for Oracle 12.1 and Oracle 11.

- Add monitoring of Oracle ASM disk groups.

- Add metrics for monitoring Oracle resource manager.

- [corechecks/snmp] Load downloaded profiles

- DBM: Add configuration option to SQL obfuscator to use go-sqllexer package to run SQL obfuscation and normalization

- Support filtering metrics from endpoint and service checks based
  on namespace when the `DD_CONTAINER_EXCLUDE_METRICS` environment
  variable is set.

- The Windows Event Log tailer saves its current position in an event log and
  resumes reading from that location when the Agent restarts. This allows
  the Agent to collect events created before the Agent starts.


.. _Release Notes_7.50.0_Enhancement Notes:

Enhancement Notes
-----------------

- [corechecks/snmp] Support symbol modifiers for global metric tags and metadata tags.

- Update the go-systemd package to the latest version (22.5.0).

- Added default peer tags for APM stats aggregation which can be enabled through a new flag (`peer_tags_aggregation`).

- Add a stop timeout to the Windows Agent services. If an Agent service
  does not cleanly stop within 15 seconds after receiving a stop command
  from the Service Control Manager, the service will hard stop.
  The timeout can be configured by setting the DD_WINDOWS_SERVICE_STOP_TIMEOUT_SECONDS
  environment variable.
  Agent stop timeouts are logged to the Windows Event Log and can be monitored and alerted on.

- APM: OTLP: Add support for custom container tags via resource attributes prefixed by `datadog.container.tag.*`.

- Agents are now built with Go ``1.20.11``.

- CWS: Support for Ubuntu 23.10.
  CWS: Reduce memory usage of ring buffer on machines with more than 64 CPU cores.
  CSPM: Move away from libapt to run Debian packages compliance checks.

- DBM: Bump the minimum version of the `go-sqllexer` library to 0.0.7 to support collecting stored procedure names.

- Add subcommand `diagnose show-metadata gohai` for gohai data

- Upgraded JMXFetch to ``0.49.0`` which adds some more telemetry
  and contains some small fixes.

- Netflow now supports the `datadog-agent status` command, providing
  configuration information. Any configuration errors encountered will be
  listed.

- Emit `database_instance` tag with the value `host/cdb`. The goal is to show each database separately in the DBM entry page. Currently, the backend initializes `database_instance` to `host`.
  Also, the Agent will emit the new `db_server` tag because we have to initialize the `host` tag to `host/cdb`.

- Improve obfuscator formatting. Prevent spaces after parentheses.
  Prevent spaces before `#` when `#` is a part of an identifier.

- Emit query metrics with zero executions to capture long runners spanning over several sampling periods.

- Impose a time limit on query metrics processing. After exceeding the default limit of 20s, the Agent stops emitting execution plans and fqt events.

- Add `oracle.inactive_seconds` metric. Add tags with session attributes to `oracle.process_pga*` metrics.

- Stop override peer.service with other attributes in OTel spans.

- Process-Agent: Improved parsing performance of the '/proc/pid/stat' file (Linux only)

- [snmp_listener] Enable ``collect_topology`` by default.

- dbm: add SQL obfuscation options to give customer more control over how SQL is obfuscated and normalized.
  - ``RemoveSpaceBetweenParentheses`` - remove spaces between parentheses. This option is only valid when ``ObfuscationMode`` is ``obfuscate_and_normalize``.
  - ``KeepNull` - disable obfuscating null values with ?. This option is only valid when ``ObfuscationMode`` is "obfuscate_only" or ``obfuscate_and_normalize``.
  - ``KeepBoolean`` - disable obfuscating boolean values with ?. This option is only valid when ``ObfuscationMode`` is ``obfuscate_only`` or ``obfuscate_and_normalize``.
  - ``KeepPositionalParameter`` - disable obfuscating positional parameters with ?. This option is only valid when ``ObfuscationMode`` is ``obfuscate_only`` or ``obfuscate_and_normalize``.

- Add logic to support multiple tags created by a single label/annotaion.
  For example, add the following config to extract tags for chart_name and app_chart_name.
    podLabelsAsTags:
      chart_name: chart_name, app_chart_name
  Note: the format must be a comma-separated list of tags.

- The logs collection pipeline has been through a refactor to support
  processing only the message content (instead of the whole raw message)
  in the journald and Windows events tailers.
  This feature is experimental and off by default since it changes how
  existing `log_processing_rules` behaves with journald and Windows events
  tailer.
  Note that it will be switched on by default in a future release of the Agent.
  A warning notifying about this is shown when the journald and Windows events
  tailers are used with some `log_processing_rules`.

- The Datadog agent container image is now using Ubuntu 23.10 mantic
  as the base image.

- The win32_event_log check now continuously collects and reports events instead of waiting for
  ``min_collection_interval`` to collect.
  ``min_collection_interval`` now controls how frequently the check attempts to reconnect
  when the event subscription is in an error state.


.. _Release Notes_7.50.0_Deprecation Notes:

Deprecation Notes
-----------------

- Installing the Agent on Windows Server versions lower than 2016 and client versions lower than 10 is now deprecated.

- The ``timeout`` option for the win32_event_log check is no longer applicable and can be removed. If the option
  is set, the check logs a deprecation warning and ignores the option.


.. _Release Notes_7.50.0_Security Notes:

Security Notes
--------------

- Fix ``CVE-2023-45283`` and ``CVE-2023-45284``

- Update OpenSSL from 3.0.11 to 3.0.12.
  This addresses CVE-2023-5363.


.. _Release Notes_7.50.0_Bug Fixes:

Bug Fixes
---------

- On Windows, uninstalling the Agent should not fail if the Datadog Agent registry key is missing.

- APM: OTLP: Only extract DD container tags from resource attributes. Previously, container tags were also extracted from span attributes.

- APM: OTLP: Only add container tags in tag `_dd.tags.container`. Previously, container tags were also added as span tags.

- Resolved an issue in the containerd collector where the SBOM collection did not correctly attach RepoTags and RepoDigests to the SBOM payload.

- Add a workaround for a bug in a Windows API that can cause the Agent to
  crash when collecting forwarded events from the Windows Event Log.

- Resolve the issue with hostname resolution in the kube_apiserver provider when the useHostNetwork setting is enabled.

- Fix an issue that prevented process ID (PID) from being associated with containers in Live Container View when the Agent is deployed in AWS Fargate.

- APM: Fixed trace-agent not forwarding errors from remote configuration and reporting them all as 500s

- On Windows, the `SE_DACL_AUTO_INHERITED` flag is reset on `%PROJECTLOCATION%` during upgrades and uninstalls.

- Fixes a bug in the Windows NPM driver where NPM displays byte overcounts.

- For USM on Windows, fixes the problem where paths were being erroneously
  reported as truncated

- Fixes journald log's Seek function to be set at the beginning or end upon initialization.

- Fixed the cause of some crashes related to CPU instruction
  incompatibility happening under certain CPUs when making calls to
  the included libgmp library.

- [kubelet] The Kubelet client no longer fails to initialize when the parameter ``kubelet_tls_verify`` is set to ``false`` with a misconfigured root certificate authority.

- Fixes a bug where the process-agent process check command would fail to run
  when language detection was enabled.

- Document query metrics `metric_prefix` parameter.

- Set the tag `dd.internal.resource:database_instance` to `host` instead of `host/cdb`.

- Switch to the new obfuscator where bugs such as getting an error when obfuscating `@!` and where comments on DMLs weren't being removed are fixed.

- Fixes wrong values in Oracle query metrics data. Extreme cases had inflated statistics and missing statements. The affected were pure DML and PL/SQL statements.

- Fix the bug that prevented Oracle DBM working properly on AWS RDS non-multitenant instances.

- Fix an issue that caused the win32_event_log check to not stop running when the rate of incoming event
  records was higher than the ``timeout`` option. The ``timeout`` option is now deprecated.

- The Windows Event Log tailer automatically recovers and is able to resume collecting
  events when a log provider is reinstalled, which sometimes happens during Windows updates.


.. _Release Notes_7.49.1:

7.49.1 / 6.49.1
======

.. _Release Notes_7.49.1_Prelude:

Prelude
-------

Release on: 2023-11-15

- Please refer to the `7.49.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7491>`_ for the list of changes on the Core Checks


.. _Release Notes_7.49.1_Bug Fixes:

Bug Fixes
---------

- CWS: add ``arch`` field into agent context included in CWS events.

- APM: Fix a deadlock issue which can prevent the trace-agent from shutting down.

- CWS: Fix the broken lineage check for process activity in CWS.

- APM: fix a regression in the Trace Agent that caused container tagging
  with UDS and cgroup v2 to fail.


.. _Release Notes_7.49.0:

7.49.0 / 6.49.0
======

.. _Release Notes_7.49.0_Prelude:

Prelude
-------

Release on: 2023-11-02

- Refer to the `7.49.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7490>`_ for the list of changes on the core checks


.. _Release Notes_7.49.0_New Features:

New Features
------------

- Add --use-unconnected-udp-socket flag to agent snmp walk command.

- Add support for image pull metrics in the containerd check.

- Add kubelet stats.summary check (kubernetes_core.kubelet.*) to the Agent's core checks to replace the old kubernetes.kubelet check generated from Python.

- APM: [BETA] Adds `peer_tags` configuration to allow for more tags in APM stats that
  can add granularity and clarity to a `peer.service`. To set this config, use
  ``DD_APM_PEER_TAGs='["aws.s3.bucket", "db.instance", ...]`` or
  ``apm_config.peer_tags: ["aws.s3.bucket", "db.instance", ...]`` in datadog.yaml.
  Please note that ``DD_APM_PEER_SERVICE_AGGREGATION`` or ``apm_config.peer_service_aggregation`` must also be set to ``true``.

- Introduces new Windows crash detection check.  Upon initial check
  run, sends a DataDog event if it is determined that the machine has
  rebooted due to a system crash.

- Install the Aerospike integration on ARM platforms for Python 3

- CWS: Detect patterns in processes and files paths to improve
  accuracy of anomaly detections.

- Add Dynamic Instrumentation diagnostics proxy endpoint to the trace-agent http server.

  At present, diagnostics are forwarded through the debugger endpoint on the trace-agent server to logs.
  Since Dynamic Instrumentation also allows adding dynamic metrics and dynamic spans, we want to remove the
  dependency on logs for diagnostics - the new endpoint uploads diagnostic messages on a dedicated track.

- Adds a configurable jmxfetch telemetry check that collects additional data on the
  running jmxfetch JVM in addition to data about the JVMs jmxfetch is monitoring.
  The check can be configured by enabling the jmx_telemetry_enabled option in the Agent.

- [NDM] Collect diagnoses from SNMP devices.

- Adding support for Oracle 12.2.

- Add support for Oracle 18c.

- CWS now computes hashes for all the files involved in the generation of a Security Profile and an Anomaly Detection Event

- [Beta] Cluster agent supports APM Single Step Instrumentation for Kubernetes.
  Can be enabled in Kubernetes cluster by setting ``DD_APM_INSTRUMENTATION_ENABLED=true`.
  Single Step Instrumentation can be turned on in specific namespaces using
  environment variable DD_APM_INSTRUMENTATION_ENABLED_NAMESPACES.
  Single Step Instrumentation can be turned off in specific namespaces using
  environment variable DD_APM_INSTRUMENTATION_DISABLED_NAMESPACES.


.. _Release Notes_7.49.0_Enhancement Notes:

Enhancement Notes
-----------------

- Moving the Orchestrator Explorer pod check from the process agent to the core agent. In the following release we will be removing the process agent check and defaulting to the core agent check. If you want to migrate ahead of time you can set ``orchestrator_explorer.run_on_node_agent`` = true in your configuration.

- Add new GPU metrics in the KSM Core check:
    - ``kubernetes_state.node.gpu_capacity`` tagged by ``node``, ``resource``, ``unit`` and ``mig_profile``.
    - ``kubernetes_state.node.gpu_allocatable`` tagged by ``node``, ``resource``, ``unit`` and ``mig_profile``.
    - ``kubernetes_state.container.gpu_limit`` tagged by kube_namespace, pod_name, kube_container_name, ``node``, ``resource``, ``unit`` and ``mig_profile``.

- Tag container entity with ``image_id`` tag.

- ``max_message_size_bytes`` can now be configured in ``logs_config``. This allows the default message
  content limit of 256,000 bytes to be increased up to 1MB. If a log line is larger than this byte limit,
  the overflow bytes will be truncated.

- APM: Add regex support for filtering tags by apm_config.filter_tags_regex or environment
  variables DD_APM_FILTER_TAGS_REGEX_REQUIRE and DD_APM_FILTER_TAGS_REGEX_REJECT.

- Agents are now built with Go ``1.20.10``.

- CWS: Support fentry/fexit eBPF probes which provide lower overhead than
  kprobe/kretprobes (currently disabled by default and supported only
  on Linux kernel 5.10 and later).

- CWS: Improved username resolution in containers and handle their creation
  and deletion at runtime.

- CWS: Apply policy rules on processes already present at startup.

- CWS: Reduce memory usage of BTF symbols.

- Remote Configuration for Cloud Workload Security detection rules is enabled if Remote Configuration is globally enabled for the Datadog Agent.
  Remote Configuration for Cloud Workload Security can be disabled while Remote Configuration is globally enabled by setting the `runtime_security_config.remote_configuration.enabled` value to false.
  Remote Configuration for Cloud Workload Security cannot be enabled if Remote Configuration is not globally enabled.

- Add ``gce-container-declaration`` to default GCE excluded host tags. See ``exclude_gce_tags`` configuration settings for more.

- Add metrics for the workloadmeta extractor to process-agent status output

- Add a heartbeat mechanism for SBOM collection to avoid having to
  send the whole SBOM if it has not changed since the last computation.
  The default interval for the host SBOM has changed from 24 hours to 1 hour.

- Prefix every entry in the log file with details about the database server and port to distinguish log entries originating from different databases.

- JMXFetch internal telemetry is now included in the ``agent status`` output when
  the verbose flag is included in the request.

- Sensitive information is now scrubbed from pod annotations.

- The image_id tag no longer includes the ``docker-pullable://`` prefix when using Kubernetes with Docker as runtime.

- Improve SQL text collection for self-managed installations. The Agent selects text from `V$SQL` instead of `V$SQLSTATS`. If it isn't possible to query the text, the Agent tries to identify the context, such as parsing or closing cursor, and put it in the SQL text.

- Improve the Oracle check example configuration file.

- Collect Oracle execution plans by default.

- Add global custom queries to Oracle checks.

- Add connection refused handling.

- Add the `hosting-type` tag, which can have one of the following values: `self-managed`, `RDS`, or `OCI`.

- Add a hidden parameter to log unobfuscated execution plan information.

- Adding `real_hostname` tag.

- Add `sql_id` and `plan_hash_value` to obfuscation error message.

- Add Oracle ``pga_over_allocation_count_metric``.

- Add information about missing privileges with the link to the `grant` commands.

- Add TCPS configuration to `conf.yaml.example`.

- The `container` check reports two new metrics:

    * ``container.memory.page_faults``
    * ``container.memory.major_page_faults``

    to report the page fault counters per container.

- prometheus_scrape: Adds support for multiple OpenMetrics V2 features in the ``prometheus_scrape.checks[].configurations[]`` items:
    * ``exclude_metrics_by_labels``
    * ``raw_line_filters``
    * ``cache_shared_labels``
    * ``use_process_start_time``
    * ``hostname_label``
    * ``hostname_format``
    * ``telemetry``
    * ``ignore_connection_errors``
    * ``request_size``
    * ``log_requests``
    * ``persist_connections``
    * ``allow_redirects``
    * ``auth_token``
  For a description of each option, refer to the sample configuration in https://github.com/DataDog/integrations-core/blob/master/openmetrics/datadog_checks/openmetrics/data/conf.yaml.example.

- Improved the SBOM check function to now communicate the status of scans and any potential errors directly
  to DataDog for more streamlined error management and resolution.

- Separate `init-containers` from `containers` in the `KubernetesPod` structure of workloadmeta.

- Improve marshalling performance in the ``system-probe`` -> ``process-agent`` path. This improves memory footprint when NPM and/or USM are enabled.

- Raise the default ``logs_config.open_files_limit`` to ``500`` on
  Windows.


.. _Release Notes_7.49.0_Deprecation Notes:

Deprecation Notes
-----------------

- `service_monitoring_config.enable_go_tls_support` is deprecated and replaced by `service_monitoring_config.tls.go.enabled`.
  `network_config.enable_https_monitoring` is deprecated and replaced by `service_monitoring_config.tls.native.enabled`.


.. _Release Notes_7.49.0_Security Notes:

Security Notes
--------------

- APM: The Agent now obfuscates the entire Memcached command by
  default. You can revert to the previous behavior where only the values
  were obfuscated by setting ``DD_APM_OBFUSCATION_MEMCACHED_KEEP_COMMAND=true``
  or ``apm_config.obfuscation.memcached.keep_command: true`` in datadog.yaml.

- Fix ``CVE-2023-39325``

- Bump ``golang.org/x/net`` to v0.17.0 to fix CVE-2023-44487.


.. _Release Notes_7.49.0_Bug Fixes:

Bug Fixes
---------

- Fix Agent Flare not including Trace Agent's expvar output.

- Fixes a panic that occurs when the Trace Agent receives an OTLP payload during shutdown

- Fixes a crash upon receiving an OTLP Exponential Histogram with no buckets.

- CWS: Scope network context to DNS events only as it may not be available
  to all events.

- CWS: Fix a bug that caused security profiles of already running workloads
  to be empty.

- The ``docker.cpu.shares`` metric emitted by the Docker check now reports the correct number of CPU shares when running on cgroups v2.

- Fixes a critical data race in ``workloadmeta`` that was causing issues when a subscriber attempted to unsubscribe while events were being handled in another goroutine.

- Fix misnamed metric in the trace-agent.

- Fixed a problem that caused the Agent to miss some image labels when using
  ``containerd`` as the container runtime.

- Fix config conflict preventing ``logs_config.use_podman_logs`` from working

- The scubbing logic for configurations now scrubs YAML lists. This fixes ``flare_stripped_keys`` not working on YAML
  list.

- Fixed an issue in the SBOM check when using Kubernetes with Docker as runtime. Some images used by containers were incorrectly marked as unused.

- Fix Oracle SQL text truncation in query samples.

- Make the custom queries feature available for non-DBM users.

- Fix wrong tags generated by custom queries.

- Eliminate duplicate upper case ``cdb`` and ``pdb`` tags.

- Fix `panic: runtime error: invalid memory address or nil pointer dereference` in `StatementMetrics` by improving cache handling.

- Fix truncation of SQL text for large statements.

- Fix the `failed to query v$pdbs`, which was appearing for RDS databases.

- Bug fix for `ORA-06502: PL/SQL: numeric or value error: character string buffer too small`. This error would occasionally appear during activity sampling.

- Adjust doc links to grant privilege commands for multitenant and non-CDB architecture.

- Workaround for the PGA memory leak.

- Improve recovering from lost connections in custom queries.

- Emit zero value for oracle.pga_over_allocation metric.

- APM: Parse SQL Server query with single dollar identifier ``$action``.


.. _Release Notes_7.49.0_Other Notes:

Other Notes
-----------

- JMXFetch upgraded to `0.48.0 <https://github.com/DataDog/jmxfetch/releases/tag/0.48.0>`_


.. _Release Notes_7.48.1:

7.48.1 / 6.48.1
======

.. _Release Notes_7.48.1_Prelude:

Prelude
-------

Release on: 2023-10-17

- Please refer to the `7.48.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7481>`_ for the list of changes on the Core Checks


.. _Release Notes_7.48.1_Upgrade Notes:

Upgrade Notes
-------------

- Upgraded Python 3.9 to Python 3.9.18


.. _Release Notes_7.48.1_Security Notes:

Security Notes
--------------

- Bump embedded curl version to 8.4.0 to fix CVE-2023-38545 and CVE-2023-38546

- Updated the version of OpenSSL used by Python on Windows to `1.1.1w`; addressed CVE-2023-4807, CVE-2023-3817, and CVE-2023-3446


.. _Release Notes_7.48.1_Bug Fixes:

Bug Fixes
---------

- On some slow drives, when the Agent shuts down suddenly the Logs Agent registry file can become corrupt.
  This means that when the Agent starts again the registry file can't be read and therefore the Logs Agent reads logs from the beginning again.
  With this update, the Agent now attempts to update the registry file atomically to reduce the chances of a corrupted file.


.. _Release Notes_7.48.0:

7.48.0 / 6.48.0
======

.. _Release Notes_7.48.0_Prelude:

Prelude
-------

Release on: 2023-10-10

- Please refer to the `7.48.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7480>`_ for the list of changes on the Core Checks


.. _Release Notes_7.48.0_Upgrade Notes:

Upgrade Notes
-------------

- The EventIDs logged to the Windows Application Event Log by the Agent services
  have been normalized and now have the same meaning across Agent services.
  Some EventIDs have changed and the rendered message may be incorrect
  if you view an Event Log from a host that uses a different version of the Agent
  than the host that created the Event Log. To ensure you see the correct message,
  choose "Display information for these languages" when exporting the Event
  Log from the host. This does not affect Event Logs collected by the Datadog Agent's
  Windows Event Log integration, which renders the event messages on the originating host.
  The EventIDs and messages used by the Agent services can be viewed in
  ``pkg/util/winutil/messagestrings/messagestrings.mc``.

- ``datadog-connectivity`` and ``metadata-availability`` subcommands
  do not exist anymore and their diagnoses are reported in a more
  general and structured way.

  Diagnostics previously reported via ``datadog-connectivity``
  subcommand will be reported now as part of
  ``connectivity-datadog-core-endpoints``suite. Correspondingly,
  diagnostics previously reported via ``metadata-availability``
  subcommand will be reported now as part of
  ``connectivity-datadog-autodiscovery`` suite.

- Streamlined settings by renaming `workloadmeta.remote_process_collector.enabled` and `process_config.language_detection.enabled` to `language_detection.enabled`.

- The command line arguments to the Datadog Agent Trace Agent ``trace-agent``
  have changed from single-dash arguments to double-dash arguments.
  For example, ``-config`` must now be provided as ``--config``.
  Additionally, subcommands have been added, these may be listed with the
  ``--help`` switch. For backward-compatibility reasons the old CLI arguments
  will still work in the foreseeable future but may be removed in future versions.


.. _Release Notes_7.48.0_New Features:

New Features
------------

- Added the kubernetes_state.pod.tolerations metric to the KSM core check

- Grab, base64 decode, and attach trace context from message attributes passed through SNS->SQS->Lambda

- Add kubelet healthz check (check_run.kubernetes_core.kubelet.check) to the Agent's core checks to replace the old kubernetes.kubelet.check generated from Python.

- Tag the aws.lambda span generated by the datadog-extension with a language tag based on runtime information in dotnet and java cases

- Extended the "agent diagnose" CLI command to allow the easy addition of new
  diagnostics for diverse and dispersed Agent code.

- Add support for the ``otlp_config.metrics.sums.initial_cumulative_monotonic_value`` setting.

- [BETA] Adds Golang language and version detection through the system probe. This beta feature can be enabled by setting
  ``system_probe_config.language_detection.enabled`` to ``true`` in your ``system-probe.yaml``.

- Add new kubelet corecheck, which will eventually replace the existing kubelet check.

- Add custom queries to Oracle monitoring.

- Adding new configuration setting ``otlp_config.logs.enabled`` to enable/disable logs support  in the OTLP ingest endpoint.

- Add logsagentexporter, which is used in OTLP agent to translate ingested logs and forward them to logs-agent

- Flush in-flight requests and pending retries to disk at shutdown when disk-based buffering of metrics is enabled
  (for example, when `forwarder_storage_max_size_in_bytes` is set).

- Added a new collector in the process agent in workloadmeta.
  This collector allows for collecting processes when the `process_config.process_collection.enabled` is false
  and `language_detection.enabled` is true.
  The interval at which this collector collects processes can be adjusted with the setting
  `workloadmeta.local_process_collector.collection_interval`.

- Tag lambda cold starts and proactive initializations on the root aws.lambda span

- APM - This change improves the acceptance and queueing strategy for trace
  payloads sent to the Trace Agent. These changes create a system of
  backpressure in the Trace Agent, causing it to reject payloads when it
  cannot keep up with the rate of traffic, rather than buffering and causing
  OOM issues.

  This change has been shown to increase overall throughput in the Trace Agent
  while decreasing peak resource usage. Existing configurations for CPU and
  memory work at least as well, and often better, with these changes compared to previous Agent versions. This means users do not have to adjust
  their configuration to take advantage of these changes, and they do not
  experience performance degredation as a result of upgrading.


.. _Release Notes_7.48.0_Enhancement Notes:

Enhancement Notes
-----------------

- When `jmx_use_container_support` is enabled you can use `jmx_max_ram_percentage` to set a maximum JVM heap size based off a percentage of the total container memory.

- SNMP profile detection now updates the SNMP profile for a given IP if the device at that IP changes.

- Add ``Process Language Detection Enabled`` in the output of the Agent Status command under the ``Process Agent`` section.

- Improve ``agent diagnose`` command to be executed in context of
  running Agent process.

- Agents are now built with Go ``1.20.7``. This version of Golang fixes ``CVE-2023-29409``.

- Added the ``container.memory.usage.peak`` metric to the container check. It shows the maximum memory usage recorded since the container started.

- Unified ``agent diagnose`` CLI command by removing ``all``,
  ``datadog-connectivity``, and ``metadata-availability`` subcommands.
  These separate subcommands became one of the diagnose suites. The
  ``all`` subcommand became unnecessary.

- APM: Improved performance and memory consumption in obfuscation, both halved on average.

- Agents are now built with Go ``1.20.8``.

- The processor frequency sent in metadata is now a decimal value on Darwin and Windows,
  as it already is on Linux. The precision of the value is increased on Darwin.

- CPU metadata which failed to be collected is no longer sent as empty values on Windows.

- Platform metadata which failed to be collected is no longer sent as empty values on Windows.

- Filesystem metadata is now collected without running the `df` binary on Unix.

- Adds language detection support for JRuby, which is detected as Ruby.

- Add the `oracle.can_connect` metric.

- Add duration to the plan payload.

- Increasing the collection interval for all the checks except for activity samples from 10s to 60s.

- Collect the number of CPUs and physical memory.

- Improve Oracle query metrics algorithm and the fetching time for execution plans.

- OTLP ingest pipeline panics no longer stop the Datadog Agent and instead
  only shutdown this pipeline. The panic is now available in the OTLP status section.

- During the process check, collect the command name from `/proc/[pid]/comm`. This
  allows more accurate language detection of processes.

- Change how SNMP trap variables with bit enumerations are resolved to hexadecimal strings prefixed with "0x" (previously base64 encoded strings).

- The Datadog agent container image is now using Ubuntu 23.04 lunar
  as the base image.

- Upgraded JMXFetch to `0.47.10 <https://github.com/DataDog/jmxfetch/releases/0.47.10>`.
  This version improves how JMXFetch communicates with the Agent, and fixes a race condition
  where an exception is thrown if the Agent hasn't finished initializing before JMXFetch starts to shut down.

- Added ``collector.worker_utilization`` to the telemetry. This metric represents the amount of time that a runner worker has been running checks.


.. _Release Notes_7.48.0_Deprecation Notes:

Deprecation Notes
-----------------

- The command line arguments to the Datadog Agent Trace Agent ``trace-agent``
  have changed from single-dash arguments to double-dash arguments.
  For example, ``-config`` must now be provided as ``--config``. For backward-
  compatibility reasons the old CLI arguments will still work in the foreseeable
  future but may be removed in future versions.


.. _Release Notes_7.48.0_Security Notes:

Security Notes
--------------

- APM: In order to improve the default customer experience regarding
  sensitive data, the Agent now obfuscates database statements within
  span metadata by default. This includes MongoDB queries,
  ElasticSearch request bodies, and raw commands from Redis and
  MemCached. Previously, this setting was off by default.
  This update could have performance implications, or obfuscate data that
  is not sensitive, and can be disabled or configured through the
  `obfuscation` options within the `apm_config`, or with the
  environment variables prefixed with `DD_APM_OBFUSCATION`. Please read the
  [Data Security documentation for full details](https://docs.datadoghq.com/tracing/configure_data_security/#trace-obfuscation).

- This update ensures the `sql.query` tag is always obfuscated by the Datadog Agent
   even if this tag was already set by a tracer or manually by a user.
   This is to prevent potentially sensitive data from being sent to Datadog.
   If you wish to have a raw, unobfuscated query within a span, then
   manually add a span tag of a different name (for example, `sql.rawquery`).

- Fix ``CVE-2023-39320``, ``CVE-2023-39318``, ``CVE-2023-39319``, and ``CVE-2023-39321``.

- Update OpenSSL from 3.0.9 to 3.0.11.
  This addresses CVEs CVE-2023-2975, CVE-2023-3446, CVE-2023-3817, CVE-2023-4807.


.. _Release Notes_7.48.0_Bug Fixes:

Bug Fixes
---------

- APM: Fix issue of ``agent status`` returning an error when run shortly after
  starting the trace agent.

- APM: Fix incorrect filenames and line numbers in logs from the trace agent.

- OTLP logs ingestion is now disabled by default. To enable it, set otlp_config.logs.enabled to true.

- Avoids fetching tags for ECS tasks when they're not consumed.

- APM: Concurrency issue at high volumes fixed in obfuscation.

- - Updated ``datadog.agent.sbom_generation_duration`` to only be observed for successful scans.

- Fixes a bug that prevents the Agent from writing permissions information
  about system-probe files when creating a flare.

- Fixed a bug that causes the Agent to report the ``datadog.agent_name.running`` metric with missing tags in some environments with cgroups v1.

- Fix ``dogstatsd_mapper_profiles`` wrong serialization when displaying the configuration (for example ``match_type``
  was shown as ``matchtype``). This also fixes a bug in which the secret management feature was incompatible with
  ``dogstatsd_mapper_profiles`` due to the renaming of the ``match_type`` key in the YAML data.

- Fix a crash in the Cluster Agent when Remote Configuration is disabled

- Corrected a bug in calculating the total size of a container image, now accounting for the configuration file size.

- Fix to the process-agent from picking up processes which are kernel
  threads due integer overflow when parsing ``/proc/<pid>/stat``.

- Fixes a rare bug in the Kubernetes State check that causes the Agent to incorrectly tag the ``kubernetes_state.job.complete`` service check.

- On Windows, the host metadata correctly reflects the Windows 11 version.

- Fix a ``datadog.yaml`` configuration file parsing issue.
  When the ``datadog.yaml`` configuration file contained a complex configuration under ``prometheus.checks[*].configurations[*].metrics``, a parsing error could lead to an OpenMetrics check not being properly scheduled. Instead, the Agent logged the following error::

    2023-07-26 14:09:23 UTC | CORE | WARN | (pkg/autodiscovery/common/utils/prometheus.go:77 in buildInstances) | Error processing prometheus configuration: json: unsupported type: map[interface {}]interface {}

- Fixes the KSM check to support HPA v2beta2 again. This stopped working in Agent v7.44.0.

- Counts sent through the no-aggregation pipeline are now sent as rate
  with a forced interval ``10`` to mimick the normal DogStatsD pipelines.

- Bug fix for the wrong query signature.

- Populate OTLP resource attributes in Datadog logs

- Changes mapping for jvm.loaded_classes from process.runtime.jvm.classes.loaded to process.runtime.jvm.classes.current_loaded

- The minimum and maximum estimation for OTLP Histogram to Datadog distribution mapping now ensures the average is within [min, max].

- This estimation is only used when the minimum and maximum are not available in the OTLP payload or this is a cumulative payload.

- Fixes a panic in the OTLP ingest metrics pipeline when sending OpenTelemetry runtime metrics

- Set correct tag value "otel_source:datadog_agent" for OTLP logs ingestion

- Removed specific environment variable filter on the Windows platform to fetch ECS task tags.

- `diagnose datadog-connectivity` subcommand now loads and resolves secrets before
  checking connectivity.

- The Agent now starts even if it cannot write events to the Application event log

- Fix Windows Service detection by replacing ``svc.IsAnInteractiveSession()`` (deprecated) with ``svc.IsWindowsService()``


.. _Release Notes_7.48.0_Other Notes:

Other Notes
-----------

- System-probe no longer tries to resolve secrets in configurations.

- Refactor in the logs collection pipeline, the `journald` and `windowsevents`
  support is now using the same pipeline as the rest of the logs collection
  implementations.

- Please note that significant changes have been introduced to the Datadog Trace
  Agent for this release. Though these changes should not alter user-facing agent
  behavior beyond the CLI changes described above, please reach out to support
  should you experience any unexpected behavior.


.. _Release Notes_7.47.1:

7.47.1 / 6.47.1
======

.. _Release Notes_7.47.1_Prelude:

Prelude
-------

Release on: 2023-09-21


.. _Release Notes_7.47.1_Bug Fixes:

Bug Fixes
---------

- Fixes issue with NPM driver restart failing with "File Not Found" error on Windows.

- APM: The ``DD_APM_REPLACE_TAGS`` environment variable and ``apm_config.replace_tags`` setting now properly look for tags with numeric values.

- Fix the issue introduced in `7.47.0` that causes the `SE_DACL_AUTO_INHERITED` flag to be removed from
  the installation drive directory when the installer fails and rolls back.


.. _Release Notes_7.47.0:

7.47.0 / 6.47.0
======

.. _Release Notes_7.47.0_Prelude:

Prelude
-------

Release on: 2023-08-31

- Please refer to the `7.47.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7470>`_ for the list of changes on the Core Checks


.. _Release Notes_7.47.0_Upgrade Notes:

Upgrade Notes
-------------

- Embedded Python 3 interpreter is upgraded to 3.9.17 in both Agent 6 and
  Agent 7. Embedded OpenSSL is upgraded to 3.0.9 in Agent 7 on Linux and
  macOS. On Windows, Python 3.9 in Agent 7 is still compiled with OpenSSL 1.1.1.


.. _Release Notes_7.47.0_New Features:

New Features
------------

- Add ability to send an Agent flare from the Datadog Application for Datadog support team troubleshooting.
  This feature requires enabling Remote Configuration.

- * Added workloadmeta remote process collector to collect process metadata from the Process-Agent and store it in the core agent.
  * Added new parameter ``workloadmeta.remote_process_collector.enabled`` to enable the workloadmeta remote process collector.
  * Added a new tag ``collector`` to ``datadog.agent.workloadmeta_remote_client_errors``.

- APM: Added support for obfuscating all Redis command arguments. For any Redis
  command, all arguments will be replaced by a single "?". Configurable using
  config variable ``apm_config.obfuscation.redis.remove_all_args`` and
  environment variable ``DD_APM_OBFUSCATION_REDIS_REMOVE_ALL_ARGS``.
  Both accept a boolean value with default value ``false``.

- Added an experimental setting `process_config.language_detection.enabled`. This enables detecting languages for processes.
  This feature is WIP.

- Added an experimental gRPC server to process-agent in order to expose process entities with their detected language.
  This feature is WIP and controlled through the process_config.language_detection.enabled setting.

- The Agent now sends its configuration to Datadog by default to be displayed in the `Agent Configuration` section of
  the host detail panel. See https://docs.datadoghq.com/infrastructure/list/#agent-configuration for more information.
  The Agent configuration is scrubbed of any sensitive information and only contains configuration you’ve set using
  the configuration file or environment variables.
  To disable this feature set `inventories_configuration_enabled` to `false`.

- The Windows installer can now send a report to Datadog in case of installation failure.

- The Windows installer can now send APM telemetry.

- Add support for Oracle Autonomous Database (Oracle Cloud Infrastructure).

- Add shared memory (a.k.a. system global area - SGA) metric for Oracle databases: `oracle.shared_memory.size`

- With this release, ``remote_config.enabled`` is set to ``true`` by default in the Agent configuration file.
  This causes the Agent to request configuration updates from the Datadog site.

  To receive configurations from Datadog, you still need to enable Remote Configuration at the organization level and enable Remote Configuration capability on your API Key from the Datadog application.
  If you don't want the Agent to request configurations from Datadog, set ``remote_config.enabled`` to ``false`` in the Agent configuration file.

- `DD_SERVICE_MAPPING` can be used to rename Serverless inferred spans' service names.

- Adds a new agent command ``stream-event-platform`` to stream the event platform payloads being generated by the agent.
  This will help diagnose issues with payload generation, and should ease validation of payload changes.


.. _Release Notes_7.47.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add two new initContainer metrics to the Kubernetes State Core check: `kubernetes_state.initcontainer.waiting` and `kubernetes_state.initcontainer.restarts`.

- Add the following sysmetrics to improve DBA/SRE/SE perspective:
  avg_synchronous_single_block_read_latency, active_background_on_cpu, active_background, branch_node_splits, consistent_read_changes,
  consistent_read_gets, active_sessions_on_cpu, os_load, database_cpu_time_ratio, db_block_changes, db_block_gets, dbwr_checkpoints,
  enqueue_deadlocks, execute_without_parse, gc_current_block_received, gc_average_cr_get_time, gc_average_current_get_time,
  hard_parses, host_cpu_utilization, leaf_nodes_splits, logical_reads, network_traffic_volume, pga_cache_hit, parse_failures,
  physical_read_bytes, physical_read_io_requests, physical_read_total_io_requests, physical_reads_direct_lobs,
  physical_read_total_bytes, physical_reads_direct, physical_write_bytes, physical_write_io_requests, physical_write_total_bytes,
  physical_write_total_io_requests, physical_writes_direct_lobs, physical_writes_direct, process_limit, redo_allocation_hit_ratio,
  redo_generated, redo_writes, row_cache_hit_ratio, soft_parse_ratio, total_parse_count, user_commits

- Pause containers from the new Kubernetes community registry (`registry.k8s.io/pause`) are now excluded by default for containers and metrics collection.

- [corechecks/snmp] Add forced type ``rate`` as an alternative to ``counter``.

- [corechecks/snmp] Add symbol level ``metric_type`` for table metrics.

- Adds support for including the span.kind tag in APM stats aggregations.

- Allow ``ad_identifiers`` to be used in file based logs integration configs
  in order to collect logs from disk.

- Agents are now built with Go ``1.20.5``

- Agents are now built with Go ``1.20.6``. This version of Golang fixes `CVE-2023-29406`.

- Improve error handling in External Metrics query logic by running
  queries with errors individually with retry and backoff, and batching
  only queries without errors.

- CPU metadata is now collected without running the `sysctl` binary on Darwin.

- Memory metadata is now collected without running the `sysctl` binary on Darwin.

- Always send the swap size value in metadata as an integer in kilobytes.

- Platform metadata is now collected without running the `uname` binary on Linux and Darwin.

- Add new metrics for resource aggregation to the Kubernetes State Core check:
  - `kubernetes_state.node.<cpu|memory>_capacity.total`
  - `kubernetes_state.node.<cpu|memory>_allocatable.total`
  - `kubernetes_state.container.<cpu|memory>_requested.total`
  - `kubernetes_state.container.<cpu|memory>_limit.total`

- The kube node name is now reported a host tag ``kube_node``

- [pkg/netflow] Collect `flow_process_nf_errors_count` metric from goflow2.

- APM: Bind ``apm_config.obfuscation.*`` parameters to new obfuscation environment variables. In particular, bind:
  ``apm_config.obfuscation.elasticsearch.enabled`` to ``DD_APM_OBFUSCATION_ELASTICSEARCH_ENABLED``:
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.elasticsearch.keep_values`` to ``DD_APM_OBFUSCATION_ELASTICSEARCH_KEEP_VALUES``
  It accepts a list of strings of the form ``["id1", "id2"]``.

  ``apm_config.obfuscation.elasticsearch.obfuscate_sql_values`` to ``DD_APM_OBFUSCATION_ELASTICSEARCH_OBFUSCATE_SQL_VALUES``
  It accepts a list of strings of the form ``["key1", "key2"]``.

  ``apm_config.obfuscation.http.remove_paths_with_digits`` to ``DD_APM_OBFUSCATION_HTTP_REMOVE_PATHS_WITH_DIGITS``,
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.http.remove_query_string`` to ``DD_APM_OBFUSCATION_HTTP_REMOVE_QUERY_STRING``,
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.memcached.enabled`` to ``DD_APM_OBFUSCATION_MEMCACHED_ENABLED``:
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.mongodb.enabled`` to ``DD_APM_OBFUSCATION_MONGODB_ENABLED``:
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.mongodb.keep_values`` to ``DD_APM_OBFUSCATION_MONGODB_KEEP_VALUES``
  It accepts a list of strings of the form ``["id1", "id2"]``.

  ``apm_config.obfuscation.mongodb.obfuscate_sql_values`` to ``DD_APM_OBFUSCATION_MONGODB_OBFUSCATE_SQL_VALUES``
  It accepts a list of strings of the form ``["key1", "key2"]``.

  ``apm_config.obfuscation.redis.enabled`` to ``DD_APM_OBFUSCATION_REDIS_ENABLED``:
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.remove_stack_traces`` to ``DD_APM_OBFUSCATION_REMOVE_STACK_TRACES``:
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.sql_exec_plan.enabled`` to ``DD_APM_OBFUSCATION_SQL_EXEC_PLAN_ENABLED``:
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.sql_exec_plan.keep_values`` to ``DD_APM_OBFUSCATION_SQL_EXEC_PLAN_KEEP_VALUES``
  It accepts a list of strings of the form ``["id1", "id2"]``.

  ``apm_config.obfuscation.sql_exec_plan.obfuscate_sql_values`` to ``DD_APM_OBFUSCATION_SQL_EXEC_PLAN_OBFUSCATE_SQL_VALUES``
  It accepts a list of strings of the form ``["key1", "key2"]``.

  ``apm_config.obfuscation.sql_exec_plan_normalize.enabled`` to ``DD_APM_OBFUSCATION_SQL_EXEC_PLAN_NORMALIZE_ENABLED``:
  It accepts a boolean value with default value false.

  ``apm_config.obfuscation.sql_exec_plan_normalize.keep_values`` to ``DD_APM_OBFUSCATION_SQL_EXEC_PLAN_NORMALIZE_KEEP_VALUES``
  It accepts a list of strings of the form ``["id1", "id2"]``.

  ``apm_config.obfuscation.sql_exec_plan_normalize.obfuscate_sql_values`` to ``DD_APM_OBFUSCATION_SQL_EXEC_PLAN_NORMALIZE_OBFUSCATE_SQL_VALUES``
  It accepts a list of strings of the form ``["key1", "key2"]``.

- The Windows installer is now built using WixSharp.

- Refactored the Windows installer custom actions in .Net.

- Remove Oracle from the Heroku build.

- [pkg/snmp/traps] Collect telemetry metrics for SNMP Traps.

- [pkg/networkdevice] Add Meraki fields to NDM Metadata payload.

- [corechecks/snmp] Add ``metric_type`` to metric root and deprecate ``forced_type``.

- [corechecks/snmp] Add ``tags`` to ``interface_configs`` to tag interface metrics

- [corechecks/snmp] Add ``user_profiles`` directory support.


.. _Release Notes_7.47.0_Deprecation Notes:

Deprecation Notes
-----------------

- The `system_probe_config.http_map_cleaner_interval_in_s` configuration has been deprecated. Use `service_monitoring_config.http_map_cleaner_interval_in_s` instead.

- The `system_probe_config.http_idle_connection_ttl_in_s` configuration has been deprecated. Use `service_monitoring_config.http_idle_connection_ttl_in_s` instead.

- The `network_config.http_notification_threshold` configuration has been deprecated. Use `service_monitoring_config.http_notification_threshold` instead.

- The `network_config.http_max_request_fragment` configuration has been deprecated. Use `service_monitoring_config.http_max_request_fragment` instead.

- The `network_config.http_replace_rules` configuration has been deprecated. Use `service_monitoring_config.http_replace_rules` instead.

- The `network_config.max_tracked_http_connections` configuration has been deprecated. Use `service_monitoring_config.max_tracked_http_connections` instead.

- The `network_config.max_http_stats_buffered` configuration has been deprecated. Use `service_monitoring_config.max_http_stats_buffered` instead.

- The `compliance_config.xccdf.enabled` configuration has been deprecated. Use `compliance_config.host_benchmarks.enabled` instead.


.. _Release Notes_7.47.0_Bug Fixes:

Bug Fixes
---------

- APM: Fix a bug introduced in Agent versions 7.44 and 6.44 that
  changed the expected strings separator from comma to space when
  multiple features are defined in DD_APM_FEATURES.
  Now either separator can be used (for example, DD_APM_FEATURES="feat1,feat2" or DD_APM_FEATURES="feat1 feat2").

- Add a workaround for erroneous database connection loss handling in go-ora.

- If no NTP servers are reachable, `datadog-agent status` now displays `ERROR` for the NTP check, rather than `OK`.

- Fixes a bug in auto-discovery annotations processing where two consecutive percent characters were wrongly altered even if they were not part of a ``%%var%%`` template variable pattern.

- Fix memory leak by closing the time ticker in orchestrator check when the check is done.

- Fixes a panic occuring when an entry in ``/etc/services`` does not follow
  the format ``port/protocol``: https://gitlab.com/cznic/libc/-/issues/25

- Fixes the inclusion of the ``security-agent.yaml`` file in the flare.

- [apm] fix an issue for service and peer.service normalization where names starting with a digit are incorrectly considered as invalid

- Fix building a local flare to use the expvar_port from the config instead of the default port.

- Use a locale-independent format for the swap size sent in the metadata,
  to avoid issues when parsing the value in the frontend.

- Fixes a bug where the metric with timestamps pipeline could have wrongly
  processed metrics without timestamps (when both pipelines were flooded),
  potentially leading to inaccuracies.

- Fixes an issue where `process_config.max_per_message` and `process_config.max_message_bytes`
  were ignored when set larger than the default values, and increases the limit on accepted values for these
  variables.

- rtloader: Use `execinfo` only if provided to fix builds on
  C libraries like `musl`.


.. _Release Notes_7.47.0_Other Notes:

Other Notes
-----------

- Service check ``datadog.agent.check_status`` is now disabled by default. To re-enable,
  set ``integration_check_status_enabled`` to ``true``.


.. _Release Notes_7.46.0:

7.46.0 / 6.46.0
======

.. _Release Notes_7.46.0_Prelude:

Prelude
-------

Release on: 2023-07-10

- Please refer to the `7.46.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7460>`_ for the list of changes on the Core Checks


.. _Release Notes_7.46.0_Upgrade Notes:

Upgrade Notes
-------------

- Refactor the SBOM collection parameters from::

    conf.d/container_lifecycle.d/conf.yaml existence (A) # to schedule the container lifecycle long running check
    conf.d/container_image.d/conf.yaml     existence (B) # to schedule the container image metadata long running check
    conf.d/sbom.d/conf.yaml                existence (C) # to schedule the SBOM long running check

    Inside datadog.yaml:

    container_lifecycle:
      enabled:                        (D)  # Used to control the start of the container_lifecycle forwarder but has been decommissioned by #16084 (7.45.0-rc)
      dd_url:                              # \
      additional_endpoints:                # |
      use_compression:                     # |
      compression_level:                   #  > generic parameters for the generic EVP pipeline
        …                                  # |
      use_v2_api:                          # /

    container_image:
      enabled:                        (E)  # Used to control the start of the container_image forwarder but has been decommissioned by #16084 (7.45.0-rc)
      dd_url:                              # \
      additional_endpoints:                # |
      use_compression:                     # |
      compression_level:                   #  > generic parameters for the generic EVP pipeline
        …                                  # |
      use_v2_api:                          # /

    sbom:
      enabled:                        (F)  # control host SBOM collection and do **not** control container-related SBOM since #16084 (7.45.0-rc)
      dd_url:                              # \
      additional_endpoints:                # |
      use_compression:                     # |
      compression_level:                   #  > generic parameters for the generic EVP pipeline
        …                                  # |
      use_v2_api:                          # /
      analyzers:                      (G)  # trivy analyzers user for host SBOM collection
      cache_directory:                (H)
      clear_cache_on_exit:            (I)
      use_custom_cache:               (J)
      custom_cache_max_disk_size:     (K)
      custom_cache_max_cache_entries: (L)
      cache_clean_interval:           (M)

    container_image_collection:
      metadata:
        enabled:                      (N)  # Controls the collection of the container image metadata in workload meta
      sbom:
        enabled:                      (O)
        use_mount:                    (P)
        scan_interval:                (Q)
        scan_timeout:                 (R)
        analyzers:                    (S)  # trivy analyzers user for containers SBOM collection
        check_disk_usage:             (T)
        min_available_disk:           (U)

  to::

    conf.d/{container_lifecycle,container_image,sbom}.d/conf.yaml no longer needs to be created. A default version is always shipped with the Agent Docker image with an underscore-prefixed ad_identifier that will be synthesized by the agent at runtime based on config {container_lifecycle,container_image,sbom}.enabled parameters.

    Inside datadog.yaml:

    container_lifecycle:
      enabled:                        (A)  # Replaces the need for creating a conf.d/container_lifecycle.d/conf.yaml file
      dd_url:                              # \
      additional_endpoints:                # |
      use_compression:                     # |
      compression_level:                   #  > unchanged generic parameters for the generic EVP pipeline
        …                                  # |
      use_v2_api:                          # /

    container_image:
      enabled:                        (B)  # Replaces the need for creating a conf.d/container_image.d/conf.yaml file
      dd_url:                              # \
      additional_endpoints:                # |
      use_compression:                     # |
      compression_level:                   #  > unchanged generic parameters for the generic EVP pipeline
        …                                  # |
      use_v2_api:                          # /

    sbom:
      enabled:                        (C)  # Replaces the need for creating a conf.d/sbom.d/conf.yaml file
      dd_url:                              # \
      additional_endpoints:                # |
      use_compression:                     # |
      compression_level:                   #  > unchanged generic parameters for the generic EVP pipeline
        …                                  # |
      use_v2_api:                          # /
      cache_directory:                (H)
      clear_cache_on_exit:            (I)
      cache:                               # Factorize all settings related to the custom cache
        enabled:                      (J)
        max_disk_size:                (K)
        max_cache_entries:            (L)
        clean_interval:               (M)

      host:                                # for host SBOM parameters that were directly below `sbom` before.
        enabled:                      (F)  # sbom.host.enabled replaces sbom.enabled
        analyzers:                    (G)  # sbom.host.analyzers replaces sbom.analyzers

      container_image:                     # sbom.container_image replaces container_image_collection.sbom
        enabled:                      (O)
        use_mount:                    (P)
        scan_interval:                (Q)
        scan_timeout:                 (R)
        analyzers:                    (S)    # trivy analyzers user for containers SBOM collection
        check_disk_usage:             (T)
        min_available_disk:           (U)


.. _Release Notes_7.46.0_New Features:

New Features
------------

- This change adds support for ingesting information such as database settings and schemas as database "metadata"

- Add the capability for the security-agent compliance module to export
  detailed Kubernetes node configurations.

- Add `unsafe-disable-verification` flag to skip TUF/in-toto verification when downloading and installing wheels with the `integrations install` command

- Add `container.memory.working_set` metric on Linux (computed as Usage - InactiveFile) and Windows (mapped to Private Working Set)

- Enabling ``dogstatsd_metrics_stats_enable`` will now enable ``dogstatsd_logging_enabled``. When enabled, ``dogstatsd_logging_enabled`` generates dogstatsd log files at:
    - For ``Windows``: ``c:\programdata\datadog\logs\dogstatsd_info\dogstatsd-stats.log``
    - For ``Linux``: ``/var/log/datadog/dogstatsd_info/dogstatsd-stats.log``
    - For ``MacOS``: ``/opt/datadog-agent/logs/dogstatsd_info/dogstatsd-stats.log``
  These log files are also automatically attached to the flare.

- You can adjust the dogstatsd-stats logging configuration by using:
    - dogstatsd_log_file_max_size: ``SizeInBytes`` (default: ``dogstatsd_log_file_max_size:"10Mb"``)
    - dogstatsd_log_file_max_rolls: ``Int`` (default: ``dogstatsd_log_file_max_rolls:3``)

- The `network_config.enable_http_monitoring` configuration has changed to `service_monitoring_config.enable_http_monitoring`.

- Add Oracle execution plans

- Oracle query metrics

- Add support for Oracle RDS multi-tenant


.. _Release Notes_7.46.0_Enhancement Notes:

Enhancement Notes
-----------------

- ``agent status -v`` now shows verbose diagnostic information.
  Added tailer-specific stats to the verbose status page with
  improved auto multi-line detection information.

- The ``health`` command from the Agent and Cluster Agent now have a configurable timeout (60 second by default).

- Add two new metrics to the Kubernetes State Core check: `kubernetes_state.configmap.count` and `kubernetes_state.secret.count`.

- The metadata payload containing the status of every integration run by the Agent is now sent one minute after startup
  and then every ten minutes after that, as before. This means that the integration status will be visible in the app one
  minute after the Agent starts instead of ten minutes. The payload waits for a minute so the Agent has time to run every configured
  integration twice and collect an accurate status.

- Adds the ability to generate an Oracle SQL trace for Agent queries

- APM: The `disable_file_logging` setting is now respected.

- Collect conditions for a variety of Kubernetes resources.

- Documents the max_recv_msg_size_mib option and DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_MAX_RECV_MSG_SIZE_MIB environment variable in the OTLP config.
  This variable is used to configure the maximum size of messages accepted by the OTLP gRPC endpoint.

- Agents are now built with Go ``1.19.10``

- Inject container tags in instrumentation telemetry payloads

- Extract the `task_arn` tag from container tags and add it as its own header.

- [pkg/netflow] Add ``flush_timestamp`` to payload.

- [pkg/netflow] Add sequence metrics.

- [netflow] Upgrade goflow2 to v1.3.3.

- Add Oracle sysmetrics, pga process memory usage, tablespace usage with pluggable database (PDB) tags

- OTLP ingestion: Support setting peer service to trace stats exported by the Agent.

- OTLP ingestion: Stop overriding service with ``peer.service``.

- OTLP ingestion: Set OTLP span kind as Datadog span meta tag ``span.kind``.

- Adds new metric `datadog.agent.otlp.runtime_metrics` when runtime metrics are being received via OTLP.

- [corechecks/snmp] Collect topology by default.

- Upgraded JMXFetch to ``0.47.9`` which has fixes to improve
  efficiency when fetching beans, fixes for process attachment
  in some JDK versions, and fixes a thread leak.


.. _Release Notes_7.46.0_Deprecation Notes:

Deprecation Notes
-----------------

- Installing the Agent on Windows Server versions lower than 2012 and client versions lower than 8.1 is now deprecated.

- The `network_config.enable_http_monitoring` configuration is now deprecated. Use `service_monitoring_config.enable_http_monitoring` instead.


.. _Release Notes_7.46.0_Security Notes:

Security Notes
--------------

- Upgraded embedded Python3 to 3.8.17; addressed CVE-2023-24329.


.. _Release Notes_7.46.0_Bug Fixes:

Bug Fixes
---------

- Fix an issue where ``auto_multi_line_detection``, ``auto_multi_line_sample_size``,
  and ``auto_multi_line_match_threshold`` were not working when set though a pod
  annotation or container label.

- Ensure the Agent detects file rotations correctly when under heavy loads.

- Fixes `kubernetes_state_core` crash when unknown resources are provided.

- Fix a file descriptors leak in the Cloud Foundry Cluster Agent.

- Fix the timeout for idle HTTP connections.

- [netflow] Rename telemetry metric tag ``device_ip`` to ``exporter_ip``.

- When present, use 'host' resource attribute as the host value on OTLP payloads to avoid double tagging.

- Remove thread count from OTel .NET runtime metric mappings.

- Fix collection of I/O and open files data in the process check.

- Fix unexpected warn log when using mapping in SNMP profiles.

- Upgrade go-ora to 2.7.6 to prevent Agent crashes due to `nil pointer dereference` in case of database connection loss.


.. _Release Notes_7.45.1:

7.45.1 / 6.45.1
======

.. _Release Notes_7.45.1_Prelude:

Prelude
-------

Release on: 2023-06-27


.. _Release Notes_7.45.1_Security Notes:

Security Notes
--------------

- Bump ncurses to 6.4 in the Agent embedded environment. Fixes CVE-2023-29491.

- Updated the version of OpenSSL used by Python to `1.1.1u`; addressed CVE-2023-2650, CVE-2023-0466, CVE-2023-0465 and CVE-2023-0464.


.. _Release Notes_7.45.0:

7.45.0 / 6.45.0
======

.. _Release Notes_7.45.0_Prelude:

Prelude
-------

Release on: 2023-06-05

- Please refer to the `7.45.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7450>`_ for the list of changes on the Core Checks


.. _Release Notes_7.45.0_New Features:

New Features
------------

- Add Topology data collection with CDP.

- APM: Addition of configuration to add ``peer.service`` to trace stats exported by the Agent.

- APM: Addition of configuration to compute trace stats on spans based on their ``span.kind`` value.

- APM: Added a new endpoint in the trace-agent API `/symdb/v1/input` that acts as a reverse proxy forwarding requests to Datadog. The feature using this is currently in development.

- Add support for confluent-kafka.

- Add support for XCCDF benchmarks in CSPM.
  A new configuration option, 'compliance_config.xccdf.enabled',
  disabled by default, has been added for enabling XCCDF benchmarks.

- Add arguments to module load events

- Oracle DBM monitoring with activity sampling. The collected samples form the foundation for database load profiling. With Datadog GUI, samples can be aggregated and filtered to identify bottlenecks.

- Add reporting of `container.{cpu|memory|io}.partial_stall` metrics based on PSI Some values when host is running with cgroupv2 enabled (Linux only).
  This metric provides the wall time (in nanoseconds) during which at least one task in the container has been stalled on the given resource.

- Adding a new option `secret_backend_remove_trailing_line_break` to remove trailing line breaks from secrets returned
  by `secret_backend_command`. This makes it easier to use secret management tools that automatically add a line break when
  exporting secrets through files.


.. _Release Notes_7.45.0_Enhancement Notes:

Enhancement Notes
-----------------

- Cluster Agent: User config, cluster Agent deployment and node Agent daemonset manifests are now added to the flare archive, when the Cluster Agent is deployed with Helm (version 3.23.0+).

- Datadog Agent running as a systemd service can optionally read
  environment variables from a text file `/etc/datadog-agent/environment`
  containing newline-separated variable assignments.
  See https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Environment

- Add ability to filter kubernetes containers based on autodiscovery annotation. Containers in a pod
  can now be omitted by setting `ad.datadoghq.com/<container_name>.exclude` as an annotation on the
  pod. Logs can now be ommitted by setting `ad.datadoghq.com/<container_name>.logs_exclude` as an
  annotation on the pod.

- Added support for custom resource definitions metrics: `crd.count` and `crd.condition`.

- * Remove BadgerDB cache for Trivy.
  * Add new custom LRU cache for Trivy backed by BoltDB and parametrized by:
  * Periodically delete unused entries from the custom cache.
  * Add telemetry metrics to monitor the cache:
    - ``sbom.cached_keys``: Number of cache keys stored in memory
    - ``sbom.cache_disk_size``: Total size, in bytes, of the database as reported by BoltDB.
    - ``sbom.cached_objects_size``: Total size, in bytes, of cached SBOM objects on disk. Limited by sbom.custom_cache_max_disk_size.
    - ``sbom.cache_hits_total``: Total number of cache hits.
    - ``sbom.cache_misses_total``: Total number of cache misses.
    - ``sbom.cache_evicts_total``: Total number of cache evicts.

- Added `DD_ENV` to the SBOMPayload in the SBOM check.

- Added `kubernetes_state.hpa.status_target_metric` and `kubernetes_state.deployment.replicas_ready` metrics part of the `kubernetes_state_core` check.

- Add support for emitting resources on metrics from tags in the
  format dd.internal.resource:type,name.

- APM: Dynamic instrumentation logs and snapshots can now be shipped to multiple Datadog logs intakes.

- Adds support for OpenTelemetry span links to the Trace Agent OTLP endpoint when converting OTLP spans (span links are added as metadata to the converted span).

- Agents are now built with Go ``1.19.9``.

- Make Podman DB path configurable for rootless environment.
  Now we can set ``$HOME/.local/share/containers/storage/libpod/bolt_state.db``.

- Add ownership information for containers to the container-lifecycle check.

- Add Pod exit timestamp to container-lifecycle check.

- The Agent now uses the `ec2_metadata_timeout` value when fetching EC2 instance tags with AWS SDK. The Agent fetches
  instance tags when `collect_ec2_tags` is set to `true`.

- Upgraded JMXFetch to ``0.47.8`` which has improvements aimed
  to help large metric collections drop fewer payloads.

- Kubernetes State Metrics Core: Adds collection of Kubernetes APIServices metrics

- Add support for URLs with the `http|https` scheme in the `dd_url` or `logs_dd_url` parameters
  when configuring endpoints.
  Also automatically detects SSL needs, based on the scheme when it is present.

- [pkg/netflow] Add NetFlow Exporter to NDM Metadata.

- SUSE RPMs are now built with RPM 4.14.3 and have SHA256 digest headers.

- ``observability_pipelines_worker`` can now be used in place of the ``vector``
  config options.

- Add an option and an annotation to skip ``kube_service`` tags on Kubernetes pods.

  When the selector of a service matches a pod and that pod is ready, its metrics are decorated with a ``kube_service`` tag.

  When the readiness of a pod flips, so does the ``kube_service`` tag. This could create visual artifacts (spikes when the tag flips) on dashboards where the queries are missing ``.fill(null)``.

  If many services target a pod, the total number of tags attached to its metrics might exceed a limit that causes the whole metric to be discarded.

  In order to mitigate these two issues, it’s now possible to set the ``kubernetes_ad_tags_disabled`` parameter to ``kube_config`` to globally remove the ``kube_service`` tags on all pods::
    kubernetes_ad_tags_disabled
      - kube_service

  It’s also possible to add a ``tags.datadoghq.com/disable: kube_service`` annotation on only the pods for which we want to remove the ``kube_service`` tag.

  Note that ``kube_service`` is the only tag that can be removed via this parameter and this annotation.

- Support OTel semconv 1.17.0 in OTLP ingest endpoint.

- When ``otlp_config.metrics.histograms.send_aggregation_metrics`` is set to ``true``,
  the OTLP ingest pipeline will now send min and max metrics for delta OTLP Histograms
  and OTLP Exponential Histograms when available, in addition to count and sum metrics.

  The deprecated option ``otlp_config.metrics.histograms.send_count_sum_metrics`` now
  also sends min and max metrics when available.

- OTLP: Use minimum and maximum values from cumulative OTLP Histograms. Values are used only when we can assume they are from the last time window or otherwise to clamp estimates.

- The OTLP ingest endpoint now supports the same settings and protocol as the OpenTelemetry Collector OTLP receiver v0.75.0.

- Secrets with `ENC[]` notation are now supported for proxy setting from environment variables. For more information
  you can refer to our [Secrets Management](https://docs.datadoghq.com/agent/guide/secrets-management/)
  and [Agent Proxy Configuration](https://docs.datadoghq.com/agent/proxy/) documentations.

- [corechecks/snmp] Adds ability to send constant metrics in SNMP profiles.

- [corechecks/snmp] Adds ability to map metric tag value to string in SNMP profiles.

- [corechecks/snmp] Add support to format bytes into ip_address


.. _Release Notes_7.45.0_Deprecation Notes:

Deprecation Notes
-----------------

- APM OTLP: Field UsePreviewHostnameLogic is deprecated, and usage of this field has been removed. This is done in preparation to graduate the exporter.datadog.hostname.preview feature gate to stable.

- The Windows Installer NPM feature option, used in ``ADDLOCAL=NPM`` and ``REMOVE=NPM``, no
  longer controls the install state of NPM components. The NPM components are now always
  installed, but will only run when enabled in the agent configuration. The Windows Installer
  NPM feature option still exists for backwards compatability purposes, but has no effect.

- Deprecate ``otlp_config.metrics.histograms.send_count_sum_metrics`` in favor of ``otlp_config.metrics.histograms.send_aggregation_metrics``.

- Removed the `--info` flag in the Process Agent, which has been replaced by the `status` command since 7.35.


.. _Release Notes_7.45.0_Security Notes:

Security Notes
--------------

- Handle the return value of Close() for writable files in ``pkg/forwarder``

- Fixes cwe 703. Handle the return value of Close() for writable files and forces writes to disks
  in `system-probe`


.. _Release Notes_7.45.0_Bug Fixes:

Bug Fixes
---------

- APM: Setting apm_config.receiver_port: 0 now allows enabling UNIX Socket or Windows Pipes listeners.

- APM: OTLP: Ensure that container tags are set globally on the payload so that they can be picked up as primary tags in the app.

- APM: Fixes a bug with how stats are calculated when using single span sampling
  along with other sampling configurations.

- APM: Fixed the issue where not all trace stats are flushed on trace-agent shutdown.

- Fix an issue on the pod collection where the cluster name would not
  be consistently RFC1123 compliant.

- Make the agent able to detect it is running on ECS EC2, even with a host install, i.e. when the agent isn’t deployed as an ECS task.

- Fix missing case-sensitive version of the ``device`` tag on the ``system.disk`` group of metrics.

- The help output of the Agent command now correctly displays the executable name on Windows.

- Fix resource requirements detection for containers without any request and
  limit set.

- The KSM core check now correctly handles labels and annotations with
  uppercase letters defined in the "labels_as_tags" and "annotations_as_tags"
  config attributes.

- Fixes issue where trace data drops in OTLP ingest by adding batch processor for traces, and increases the grpc message limit

- [pkg/netflow] Rename payload ``device.ip`` to ``exporter.ip``

- Fixes an issue in the process agent where in rare scenarios, negative CPU usage percentages would be reported for processes.

- When a pod was annotated with ``prometheus.io/scrape: true``, the Agent used to schedule one ``openmetrics`` check per container in the pod unless a ``datadog.prometheusScrape.additionalConfigs[].autodiscovery.kubernetes_container_names`` list was defined, which restricted the potential container targets.
  The Agent is now able to leverage the ``prometheus.io/port`` annotation to schedule an ``openmetrics`` check only on the container of the pod that declares that port in its spec.

- Fixing an issue with Prometheus scrape feature when `service_endpoints` option is used where endpoint updates were missed by the Agent, causing checks to not be scheduled on endpoints created after Agent start.

- On Windows, when using USM, fixes tracking of connections made via
  localhost.


.. _Release Notes_7.44.1:

7.44.1 / 6.44.1
======

.. _Release Notes_7.44.1_Prelude:

Prelude
-------

Release on: 2023-05-16


.. _Release Notes_7.44.1_Enhancement Notes:

Enhancement Notes
-----------------

- Agents are now built with Go ``1.19.8``.

- Added optional config flag `process_config.cache_lookupid` to cache calls to `user.LookupId` in the process Agent.
  Use to minimize the number of calls to `user.LookupId` and avoid potential leak.


.. _Release Notes_7.44.1_Bug Fixes:

Bug Fixes
---------

- Fixes the inclusion of the ``security-agent.yaml`` file in the flare.


.. _Release Notes_7.44.0:

7.44.0 / 6.44.0
======

.. _Release Notes_7.44.0_Prelude:

Prelude
-------

Release on: 2023-04-26

- Please refer to the `7.44.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7440>`_ for the list of changes on the Core Checks


.. _Release Notes_7.44.0_New Features:

New Features
------------

- Added HTTP/2 parsing logic to Universal Service Monitoring.

- Adding Universal Service Monitoring to the Agent status check.
  Now Datadog has visibility into the status of Universal Service
  Monitoring. Startup failures appear in the status check.

- In the agent.log, a DEBUG, WARN, and ERROR log have been added to report
  how many file handles the core Agent process has open. The DEBUG log
  reports the info, the WARN log appears when the core Agent is over 90%
  of the OS file limit, and the ERROR log appears when the core Agent
  has reached 100% of the OS file limit. In the Agent status command, fields
  CoreAgentProcessOpenFiles and OSFileLimit have been added to the Logs
  Agent section. This feature is currently for Linux only.

- APM: Collect trace agent startup errors and successes using
  instrumentation-telemetry "apm-onboarding-event" messages.

- APM OTLP: Introduce OTLP Ingest probabilistic sampling, configurable via `otlp_config.traces.probabilistic_sampler.sampling_percentage`.

- Experimental: The Datadog Admission Controller can inject the .NET APM library into Kubernetes containers for auto-instrumentation.

- Enable CWS Security Profiles by default.

- Support the config `additional_endpoints` for Data Streams monitoring.

- Added support for collecting container image metadata when using Docker.

- Added Kafka parsing logic to system-probe

- Allow writing SECL rules against container creation time through the new `container.created_at`
  field, similar to the existing `process.container_at` field.
  The container creation time is also reported in the sent events.

- *[experimental]* CWS generates an SBOM for any running workload on the machine.

- *[experimental]* CWS events are enriched with SBOM data.

- *[experimental]* CWS activity dumps are enriched with SBOM data.

- Enable OTLP endpoint for receiving traces in the Datadog Lambda Extension.

- On Windows, when service inference is enabled, `process_context` tags can now be populated by the service name
  in the SCM. This feature can be controlled by either the `service_monitoring_config.process_service_inference.enabled` config setting
  in the user's `datadog.yaml` config file, or it can be configured via the `DD_SYSTEM_PROBE_PROCESS_SERVICE_INFERENCE_USE_WINDOWS_SERVICE_NAME`
  environment variable. This setting is enabled by default.


.. _Release Notes_7.44.0_Enhancement Notes:

- Added `kubernetes_state.hpa.status_target_metric` and `kubernetes_state.deployment.replicas_ready` metrics part of the `kubernetes_state_core` check.

- The status page now includes a ``Status render errors`` section to highlight errors that occurred while rendering it.

- APM:
    - Run the /debug/* endpoints in a separate server which uses port 5012 by default and only listens on ``127.0.0.1``. The port is configurable through ``apm_config.debug.port`` and ``DD_APM_DEBUG_PORT``, set it to 0 to disable the server.
    - Scrub the content served by the expvar endpoint.

- APM: apm_config.features is now configurable from the Agent configuration file. It was previously only configurable via DD_APM_FEATURES.

- Agents are now built with Go ``1.19.7``.

- The OTLP ingest endpoint now supports the same settings and protocol as the OpenTelemetry Collector OTLP receiver v0.71.0.

- Collect Kubernetes Pod conditions.

- Added the "availability-zone" tag to the Fargate integration. This
  matches the tag emitted by other AWS infrastructure integrations.

- Allow to report all gathered data in case of partial failure of container metrics retrieval.

- Upgraded JMXFetch to ``0.47.8`` which has improvements aimed
  to help large metric collections drop fewer payloads.

- JMXFetch upgraded to `0.47.5 <https://github.com/DataDog/jmxfetch/releases/0.47.5>`_
  which now supports pulling metrics from `javax.management.openmbean.TabularDataSupport`.
  Also contains a fix for pulling metrics from `javax.management.openmbean.TabularDataSupport`
  when no tags are specified.

- Updated chunking util and use cases to use generics. No behavior change.

- [corechecks/snmp] Add ``interface_configs`` to override interface speed.

- No longer increments TCP retransmit count when the retransmit fails.

- The OTLP ingestion endpoint now supports the same settings and protocols as the OpenTelemetry Collector OTLP receiver v0.70.0.

- Changes the retry mechanism of starting workloadmeta collectors so that
  instead of retrying every 30 seconds, it retries following an exponential
  backoff with initial interval of 1s and max of 30s. In general, this should
  help start sooner the collectors that failed on the first try.

- Added the "pull_duration" metric in the workloadmeta telemetry. It measures
  the time that it takes to pull from the collectors.


.. _Release Notes_7.44.0_Deprecation Notes:

Deprecation Notes
-----------------

- Marked the "availability_zone" tag as deprecated for the Fargate
  integration, in favor of "availability-zone".

- Configuration ``enable_sketch_stream_payload_serialization`` is now deprecated.


.. _Release Notes_7.44.0_Security Notes:

Security Notes
--------------

- The Agent now checks containerd containers `Spec` size before parsing it. Any `Spec` exceeding 2MB will not be parsed and a warning will be emitted. This impacts the `container_env_as_tags` feature and `%%hostname%%` variable resolution for environments based on `containerd` outside of Kubernetes.


.. _Release Notes_7.44.0_Bug Fixes:

Bug Fixes
---------

- APM: Fix issue where dogstatsd proxy would not work when bind address was set to localhost on MacOS.
  APM: Fix issue where setting bind_host to "::1" would break runtime metrics for the trace-agent.

- APM: Trace Agent not printing critical init errors.

- Fixes a bug where ignored container files (that were not tailed) were
  incorrectly counted against the total open files.

- Fixes the configuration parsing of the "container_lifecycle" check. Custom
  config values were not being applied.

- Corrects dogstatsd metric message validation to support all current (and some future) dogstatsd features

- Avoid panic in kubernetes_state_core check with specific Ingress
  objects configuration.

- Fixes a divide-by-zero panic when sketch serialization fails on the last metric of a given batch

- Fix issue introduced in 7.43 that prevents the Datadog Agent Manager application
  from executing from the checkbox at the end of the Datadog Agent installation when
  the installer is run by a non-elevated administrator user.

- Fixes a problem with USM and IIS on Windows Server 2022 due to a change
  in the way Microsoft reports IIS connections.

- Fixes the `labelsAsTags` parameter of the kube-state metrics core check.
  Tags were not properly formatted when they came from a label on one resource type (for example, namespace) and turned into a tag on another resource type (for example, pod).

- The OTLP ingest endpoint does not report the first cumulative monotonic sum value if the start timestamp of the timeseries matches its timestamp.

- Prevent disallowlisting on empty command line for processes in the Process Agent when encountering a failure to
  parse, use exe value instead.

- Make SNMP Listener support all authProtocol.

- Fix an issue where ``agent status`` would show incorrect system-probe status for 15 seconds as the system-probe started up.

- Fix partial loss of NAT info in system-probe for pre-existing connections.

- Replace ``;`` with ``&`` in the URL to open GUI to follow golang.org/issue/25192.

- Workloadmeta now avoids concurrent pulls from the same collector. This bug could lead to incorrect or missing data when the collectors were too slow pulling data.

- Fixes a bug that prevents the containerd workloadmeta collector from
  starting sometimes when `container_image_collection.metadata.enabled` is
  set to true.

- Fixed a bug in the SBOM collection feature. In certain cases, some SBOMs were
  not collected.


.. _Release Notes_7.44.0_Other Notes:

Other Notes
-----------

- The ``logs_config.cca_in_ad`` has been removed.


.. _Release Notes_7.43.2:

7.43.2 / 6.43.2
======

.. _Release Notes_7.43.2_Prelude:

Prelude
-------

Release on: 2023-04-20

.. _Release Notes_7.43.2_Enhancement Notes:

Enhancement Notes
-----------------

- Upgraded JMXFetch to ``0.47.8`` which has improvements aimed
  to help large metric collections drop fewer payloads.


.. _Release Notes_7.43.1:

7.43.1 / 6.43.1
======

.. _Release Notes_7.43.1_Prelude:

Prelude
-------

Release on: 2023-03-07

- Please refer to the `7.43.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7431>`_ for the list of changes on the Core Checks.


.. _Release Notes_7.43.1_Enhancement Notes:

Enhancement Notes
-----------------

- Agents are now built with Go ``1.19.6``.


.. _Release Notes_7.43.0:

7.43.0 / 6.43.0
======

.. _Release Notes_7.43.0_Prelude:

Prelude
-------

Release on: 2023-02-23

- Please refer to the `7.43.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7430>`_ for the list of changes on the Core Checks


.. _Release Notes_7.43.0_Upgrade Notes:

Upgrade Notes
-------------

- The command line arguments to the Datadog Agent Manager for Windows ``ddtray.exe``
  have changed from single-dash arguments to double-dash arguments.
  For example, ``-launch-gui`` must now be provided as ``--launch-gui``.
  The start menu shortcut created by the installer will be automatically updated.
  Any custom scripts or shortcuts that launch ``ddtray.exe`` with arguments must be updated manually.


.. _Release Notes_7.43.0_New Features:

New Features
------------

- NDM: Add snmp.device.reachable/unreachable metrics to all monitored devices.

- Add a new ``container_image`` long running check to collect information about container images.

- Enable orchestrator manifest collection by default

- Add a new ``sbom`` core check to collect the software bill of materials of containers.

- The Agent now leverages DMI (Desktop Management Interface) information on Unix to get the instance ID on Amazon EC2 when the metadata endpoint fails or
is not accessible. The instance ID is exposed through DMI only on AWS Nitro instances.
This will not change the hostname of the Agent upon upgrading, but will add it to the list of host aliases.

- Adds the option to collect and store in workloadmeta the software bill of
  materials (SBOM) of containerd images using Trivy. This feature is disabled
  by default. It can be enabled by setting
  `container_image_collection.sbom.enabled` to true.
  Note: This feature is CPU and IO intensive.


.. _Release Notes_7.43.0_Enhancement Notes:

Enhancement Notes
-----------------

- Adds a new ``snmp.interface_status`` metric reflecting the same status as within NDM.

- APM: Ported a faster implementation of NormalizeTag with a fast-path for already normalized ASCII tags. Should marginally improve CPU usage of the trace-agent.

- The external metrics server now automatically adjusts the query time window based on the Datadog metrics `MaxAge` attribute.

- Added parity to Unix-based ``permissions.log`` Flare file on
  Windows. ``permissions.log`` file list the original rights/ACL
  of the files copied into a Agent flare. This will ease
  troubleshooting permissions issues.

- [corechecks/snmp] Add `id` and `source_type` to NDM Topology Links

- Add an ``--instance-filter`` option to the Agent check command.

- APM: Disable ``max_memory`` and ``max_cpu_percent`` by default in containerized environments (Docker-only, ECS and CI).
  Users rely on the orchestrator / container runtime to set resource limits.
  Note: ``max_memory`` and ``max_cpu_percent`` have been disabled by default in Kubernetes environments since Agent ``7.18.0``.

- Agents are now built with Go ``1.19.5``.

- To reduce "cluster-agent" memory consomption when `cluster_agent.collect_kubernetes_tags`
  option is enabled, we introduce `cluster_agent.kubernetes_resources_collection.pod_annotations_exclude` option
  to exclude Pod annotation from the extracted Pod metadata.

- Introduce a new option `enabled_rfc1123_compliant_cluster_name_tag`
  that enforces the `kube_cluster_name` tag value to be
  an RFC1123 compliant cluster name. It can be disabled by setting this
  new option to `false`.

- Allows profiling for the Process Agent to be dynamically enabled from the CLI with `process-agent config set internal_profiling`. Optionally, once profiling is enabled, block, mutex, and goroutine profiling can also be enabled with `process-agent config set runtime_block_profile_rate`, `process-agent config set runtime_mutex_profile_fraction`, and `process-agent config set internal_profiling_goroutines`.

- Adds a new process discovery hint in the process agent when the regular process and container checks run.

- Added new telemetry metrics (``pymem.*``) to track Python heap usage.

- There are two default config files. Optionally, you can provide override config files.
  The change in this release is that for both sets, if the first config is inaccessible, the security agent startup process fails. Previously, the security agent would continue to attempt to start up even if the first config file is inaccessible.
  To illustrate this, in the default case, the config files are datadog.yaml and security-agent.yaml, and in that order. If datadog.yaml is inaccessible, the security agent fails immediately. If you provide overrides, like foo.yaml and bar.yaml, the security agent fails immediately if foo.yaml is inaccessible.
  In both sets, if any additional config files are missing, the security agent continues to attempt to start up, with a log message about an inaccessible config file. This is not a change from previous behavior.

- [corechecks/snmp] Add IP Addresses to NDM Metadata interfaces

- [corechecks/snmp] Add LLDP remote device IP address.

- prometheus_scrape: Adds support for `tag_by_endpoint` and `collect_counters_with_distributions` in the `prometheus_scrape.checks[].configurations[]` items.

- The OTLP ingest endpoint now supports the same settings and protocols as the OpenTelemetry Collector OTLP receiver v0.68.0.


.. _Release Notes_7.43.0_Deprecation Notes:

Deprecation Notes
-----------------

- The command line arguments to the Datadog Agent Manager for Windows ``ddtray.exe``
  have changed from single-dash arguments to double-dash arguments.
  For example, ``-launch-gui`` must now be provided as ``--launch-gui``.

- system_probe_config.enable_go_tls_support is deprecated and replaced by service_monitoring_config.enable_go_tls_support.


.. _Release Notes_7.43.0_Security Notes:

Security Notes
--------------

- Some HTTP requests sent by the Datadog Agent to Datadog endpoints were including the Datadog API key in the query parameters (in the URL).
  This meant that the keys could potentially have been logged in various locations, for example, in a forward or a reverse proxy server logs the Agent connected to.
  We have updated all requests to not send the API key as a query parameter.
  Anyone who uses a proxy to connect the Agent to Datadog endpoints should make sure their proxy forwards all Datadog headers (patricularly ``DD-Api-Key``).
  Failure to not send all Datadog headers could cause payloads to be rejected by our endpoints.


.. _Release Notes_7.43.0_Bug Fixes:

Bug Fixes
---------

- The secret command now correctly displays the ACL on a path with spaces.

- APM: Lower default incoming trace payload limit to 25MB. This more closely aligns with the backend limit. Some users may see traces rejected by the Agent that the Agent would have previously accepted, but would have subsequently been rejected by the trace intake. The Agent limit can still be configured via `apm_config.max_payload_size`.

- APM: Fix the `trace-agent -info` command when remote configuration is enabled.

- APM: Fix parsing of SQL Server identifiers enclosed in square brackets.

- Remove files created by system-probe at uninstall time.

- Fix the `kubernetes_state_core` check so that the host alias name
  creation uses a normalized (RFC1123 compliant) cluster name.

- Fix an issue in Autodiscovery that could prevent Cluster Checks containing secrets (ENC[] syntax) to be unscheduled properly.

- Fix panic due to uninitialized Obfuscator logger

- On Windows, fixes bug in which HTTP connections were not properly accounted
  for when the client and server were the same host (loopback).

- The Openmetrics check is no longer scheduled for Kubernetes headless services.


.. _Release Notes_7.43.0_Other Notes:

Other Notes
-----------

- Upgrade of the cgosymbolizer dependency to use
  ``github.com/ianlancetaylor/cgosymbolizer``.

- The Datadog Agent Manager ``ddtray.exe`` now requires admin to launch.


.. _Release Notes_7.42.0:

7.42.0 / 6.42.0
======

.. _Release Notes_7.42.0_Prelude:

Prelude
-------

Release on: 2023-01-23

- Please refer to the `7.42.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7420>`_ for the list of changes on the Core Checks


.. _Release Notes_7.42.0_Upgrade Notes:

Upgrade Notes
-------------

- Downloading and installing official checks with `agent integration install`
  is no longer supported for Agent installations that do not include an embedded
  python3.


.. _Release Notes_7.42.0_New Features:

New Features
------------

- Adding the `kube_api_version` tag to all orchestrator resources.

- Kubernetes Pod events generated by the `kubernetes_apiserver` can now
  benefit from the new `cluster-tagger` component in the Cluster-Agent.

- APM OTLP: Added compatibility for the OpenTelemetry Collector's datadogprocessor to the OTLP Ingest.

- The CWS agent now supports rules on mount events.

- Adding a configuration option, ``exclude_ec2_tags``, to exclude EC2 instance tags from being converted into host
  tags.

- Adds detection for a process being executed directly from memory without the binary present on disk.

- Introducing agent sampling rates remote configuration.

- Adds support for ``secret_backend_command_sha256`` SHA for the ``secret_backend_command`` executable. If ``secret_backend_command_sha256`` is used,
  the following restrictions are in place:
  - Value specified in the ``secret_backend_command`` setting must be an absolute path.
  - Permissions for the ``datadog.yaml`` config file must disallow write access by users other than ``ddagentuser`` or ``Administrators`` on Windows or the user running the Agent on Linux and macOS.
  The agent will refuse to start if the actual SHA256 of the ``secret_backend_command`` executable is different from the one specified by ``secret_backend_command_sha256``.
  The ``secret_backend_command`` file is locked during verification of SHA256 and subsequent run of the secret backend executable.

- Collect network devices topology metadata.

- Add support for AWS Lambda Telemetry API

- Adds three new metrics collected by the Lambda Extension

  `aws.lambda.enhanced.response_latency`: Measures the elapsed time in milliseconds from when the invocation request is received to when the first byte of response is sent to the client.

  `aws.lambda.enhanced.response_duration`: Measures the elapsed time in milliseconds between sending the first byte of the response to the client and sending the last byte of the response to the client.

  `aws.lambda.enhancdd.produced_bytes`: Measures the number of bytes returned by a function.

- Create cold start span representing time and duration of initialization of an AWS Lambda function.


.. _Release Notes_7.42.0_Enhancement Notes:

Enhancement Notes
-----------------

- Adds both the `StartTime` and `ScheduledTime` properties in the collector for Kubernetes pods.

- Add an option (`hostname_trust_uts_namespace`) to force the Agent to trust the hostname value retrieved from non-root UTS namespaces (Linux only).

- Metrics from Giant Swarm pause containers are now excluded by default.

- Events emitted by the Helm check now have "Error" status when the release fails.

- Add an ``annotations_as_tags`` parameter to the kubernetes_state_core check to allow attaching Kubernetes annotations as Datadog tags in a similar way that the ``labels_as_tags`` parameter does.

- Adds the ``windows_counter_init_failure_limit`` option.
  This option limits the number of times a check will attempt to initialize
  a performance counter before ceasing attempts to initialize the counter.

- [netflow] Expose collector metrics (from goflow) as Datadog metrics

- [netflow] Add prometheus listener to expose goflow telemetry

- OTLP ingest now uses the minimum and maximum fields from delta OTLP Histograms and OTLP ExponentialHistograms when available.

- The OTLP ingest endpoint now reports the first cumulative monotonic sum value if the timeseries started after the Datadog Agent process started.

- Added the `workload-list` command to the process agent. It lists the entities stored in workloadmeta.

- Allows running secrets in the Process Agent on Windows by sandboxing
  ``secret_backend_command`` execution to the ``ddagentuser`` account used by the Core Agent service.

- Add `process_context` tag extraction based on a process's command line arguments for service monitoring.
  This feature is configured in the `system-probe.yaml` with the following configuration:
  `service_monitoring_config.process_service_inference.enabled`.

- Reduce the overhead of using Windows Performance Counters / PDH in checks.

- The OTLP ingest endpoint now supports the same settings and protocol as the OpenTelemetry Collector OTLP receiver v0.64.1

- The OTLP ingest endpoint now supports the same settings and protocols as the OpenTelemetry Collector OTLP receiver v0.66.0.


.. _Release Notes_7.42.0_Deprecation Notes:

Deprecation Notes
-----------------

- Removes the `install-service` Windows agent command.

- Removes the `remove-service` Windows agent command.


.. _Release Notes_7.42.0_Security Notes:

Security Notes
--------------

- Upgrade the wheel package to ``0.37.1`` for Python 2.

- Upgrade the wheel package to ``0.38.4`` for Python 3.


.. _Release Notes_7.42.0_Bug Fixes:

Bug Fixes
---------

- APM: Fix an issue where container tags weren't working because of overwriting an essential tag on spans.

- APM OTLP: Fix an issue where a span's local "peer.service" attribute would not override a resource attribute-level service.

- On Windows, fixes a bug in the NPM network driver which could cause
  a system crash (BSOD).

- Create only endpoints check from prometheus scrape configuration
  when `prometheus_scrape.service.endpoint` option is enabled.

- Fix how Kubernetes events forwarding detects the Node/Host.
  * Previously Nodes' events were not always attached to the correct host.
  * Pods' events from "custom" controllers might still be not attached to
    a host if the controller doesn't set the host in the `source.host` event's field.

- APM: Fix SQL parsing of negative numbers and improve error message.

- Fix a potential panic when df outputs warnings or errors among its standard output.

- Fix a bug where a misconfig error does not show when `hidepid=invisible`

- The agent no longer wrongly resolves its hostname on ECS Fargate when
  requests to the Fargate API timeout.

- Metrics reported through OTLP ingest now have the interval property unset.

- Fix a PDH query handle leak that occurred when a counter failed to add to a query.

- Remove unused environment variables `DD_AGENT_PY` and `DD_AGENT_PY_ENV` from known environment variables in flare command.

- APM: Fix SQL obfuscator parsing of identifiers containing dollar signs.


.. _Release Notes_7.42.0_Other Notes:

Other Notes
-----------

- JMXFetch upgraded to `0.47.2 <https://github.com/DataDog/jmxfetch/releases/0.47.2>`_

- Bump embedded Python3 to `3.8.16`.


.. _Release Notes_7.41.1:

7.41.1 / 6.41.1
======

.. _Release Notes_7.41.1_Prelude:

Release on: 2022-12-21


.. _Release Notes_7.41.1_Enhancement Notes:

- Agents are now built with Go ``1.18.9``.


.. _Release Notes_7.41.0:

7.41.0 / 6.41.0
======

.. _Release Notes_7.41.0_Prelude:

Prelude
-------

Release on: 2022-12-09

- Please refer to the `7.41.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7410>`_ for the list of changes on the Core Checks


.. _Release Notes_7.41.0_Upgrade Notes:

Upgrade Notes
-------------

- Troubleshooting commands in the Agent CLI have been moved to the `diagnose` command. `troubleshooting metadata_v5`
  command is now `diagnose show-metadata v5` and `troubleshooting metadata_inventory` is `diagnose show-metadata inventory`.

- Journald launcher can now create multiple tailers on the same journal when
  ``config_id`` is specified. This change enables multiple configs to operate
  on the same journal which is useful for tagging different units.
  Note: This may have an impact on CPU usage.

- Upgrade tracer_agent debugger proxy to use logs intake API v2
  for uploading snapshots

- The Agent now defaults to TLS 1.2 instead of TLS 1.0. The ``force_tls_12`` configuration parameter has been removed since it's now the default behavior. To continue using TLS 1.0 or 1.1, you must set the ``min_tls_version`` configuration parameter to either `tlsv1.0` or `tlsv1.1`.


.. _Release Notes_7.41.0_New Features:

New Features
------------

- Added a required infrastructure to enable protocol classification for Network Performance Monitoring in the future.
  The protocol classification will allow us to label each connection with a L7 protocol.
  The features requires Linux kernel version 4.5 or greater.

- parse the snmp configuration from the agent and pass it to the integrated snmpwalk command in case the customer only provides an ip address

- The Agent can send its own configuration to Datadog to be displayed in the `Agent Configuration` section of the host
  detail panel. See https://docs.datadoghq.com/infrastructure/list/#agent-configuration for more information. The
  Agent configuration is scrubbed of any sensitive information and only contains configuration you’ve set using the
  configuration file or environment variables.

- Windows: Adds support for Windows Docker "Process Isolation" containers running on a Windows host.


.. _Release Notes_7.41.0_Enhancement Notes:

Enhancement Notes
-----------------

- APM: All spans can be sent through the error and rare samplers via custom feature flag `error_rare_sample_tracer_drop`. This can be useful if you want to run those samplers against traces that were not sampled by custom tracer sample rules. Note that even user manual drop spans may be kept if this feature flag is set.

- APM: The trace-agent will log failures to lookup CPU usage at error level instead of debug.

- Optionally poll Agent and Cluster Agent integration configuration files for changes after startup. This allows the Agent/Cluster Agent to pick up new
  integration configuration without a restart.
  This is enabled/disabled with the `autoconf_config_files_poll` boolean configuration variable.
  The polling interval is configured with the `autoconf_config_files_poll_interval` (default 60s).
  Note: Dynamic removal of logs configuration is currently not supported.

- Added telemetry for the "container-lifecycle" check.

- On Kubernetes, the "cluster name" can now be discovered by using
  the Node label `ad.datadoghq.com/cluster-name` or any other label
  key configured using to the configuration option:
  `kubernetes_node_label_as_cluster_name`

- Agents are now built with Go 1.18.8.

- Go PDH checks now all use the PdhAddEnglishCounter API to
  ensure proper localization support.

- Use the `windows_counter_refresh_interval` configuration option to limit
  how frequently the PDH object cache can be refreshed during counter
  initialization in golang. This replaces the previously hardcoded limit
  of 60 seconds.

- [netflow] Add disable port rollup config.

- The OTLP ingest endpoint now supports the same settings and protocol as the OpenTelemetry Collector OTLP receiver v0.61.0.

- The `disable_file_logging` setting is now respected in the process-agent.

- The `process-agent check [check-name]` command no longer outputs to the configured log file to reduce noise in the log file.

- Logs a warning when the process agent cannot read other processes due to misconfiguration.

- DogStatsD caches metric metadata for shorter periods of time,
  reducing memory usage when tags or metrics received are different
  across subsequent aggregation intervals.

- The ``agent`` CLI subcommands related to Windows services are now
  consistent in use of dashes in the command names (``install-service``,
  ``start-service``, and so on). The names without dashes are supported as
  aliases.

- The Agent now uses the V2 API to submit series data to the Datadog intake
  by default. This can be reverted by setting ``use_v2_api.series`` to
  false.


.. _Release Notes_7.41.0_Deprecation Notes:

Deprecation Notes
-----------------

- APM: The Rare Sampler is now disabled by default. If you wish to enable it explicitly you can set apm_config.enable_rare_sampler or DD_APM_ENABLE_RARE_SAMPLER to true.


.. _Release Notes_7.41.0_Bug Fixes:

Bug Fixes
---------

- APM: Don't include extra empty 'env' entries in sampling priority output shown by `agent status` command.

- APM: Fix panic when DD_PROMETHEUS_SCRAPE_CHECKS is set.

- APM: DogStatsD data can now be proxied through the "/dogstatsd/v1/proxy" endpoint
  and the new "/dogstatsd/v2/proxy" endpoint over UDS, with multiple payloads
  separated by newlines in a single request body.
  See https://docs.datadoghq.com/developers/dogstatsd#setup for configuration details.

- APM - remove extra error message from logs.

- Fixes an issue where cluster check metrics would be sometimes sent with the host tags.

- The containerd check no longer emits events related with pause containers when `exclude_pause_container` is set to `true`.

- Discard aberrant values (close to 18 EiB) in the ``container.memory.rss`` metric.

- Fix Cloud Foundry CAPI Metadata tags injection into application containers.

- Fix Trace Agent's CPU stats by reading correct PID in procfs

- Fix a potential panic when df outputs warnings or errors among its standard output.

- The OTLP ingest is now consistent with the Datadog exporter (v0.56+) when getting a hostname from OTLP resource attributes for metrics and traces.

- Make Agent write logs when SNMP trap listener starts and Agent
  receives invalid packets.

- Fixed a bug in the workloadmeta store. Subscribers that asked to receive
  only `unset` events mistakenly got `set` events on the first subscription for
  all the entities present in the store. This only affects the
  `container_lifecycle` check.

- Fix missing tags on the ``kubernetes_state.cronjob.complete`` service check.

- In ``kubernetes_state_core`` check, fix the `labels_as_tags` feature when the same Kubernetes label must be turned into different Datadog tags, depending on the resource:

     labels_as_tags:
       daemonset:
         first_owner: kube_daemonset_label_first_owner
       deployment:
         first_owner: kube_deployment_label_first_owner

- Normalize the EventID field in the output from the windowsevent log tailer.
  The type will now always be a string containing the event ID, the sometimes
  present qualifier value is retained in a new EventIDQualifier field.

- Fix an issue where the security agent would panic, sending on a close
  channel, if it received a signal when shutting down while all
  components were disabled.

- Fix tokenization of negative numeric values in the SQL obfuscator to remove extra characters prepended to the byte array.


.. _Release Notes_7.40.1:

7.40.1
======

.. _Release Notes_7.40.1_Prelude:

Prelude
-------

Release on: 2022-11-09

- Please refer to the `7.40.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7401>`_ for the list of changes on the Core Checks


.. _Release Notes_7.40.1_Enhancement Notes:

Enhancement Notes
-----------------

- Agents are now built with Go 1.18.8.


.. _Release Notes_7.40.1_Bug Fixes:

Bug Fixes
---------

- Fix log collection on Kubernetes distributions using ``cri-o`` like OpenShift, which
  began failing in 7.40.0.

.. _Release Notes_7.40.0:

7.40.0 / 6.40.0
======

.. _Release Notes_7.40.0_Prelude:

Prelude
-------

Release on: 2022-11-02

- Please refer to the ``7.40.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7400>``_ for the list of changes on the Core Checks


.. _Release Notes_7.40.0_Upgrade Notes:

Upgrade Notes
-------------

- Starting Agent 7.40, the Agent will fail to start when unable to determine hostname instead of silently using unrelevant hostname (usually, a container id).
  Hostname resolution is key to many features and failure to determine hostname means that the Agent is not configured properly.
  This change mostly affects Agents running in containerized environments as we cannot rely on OS hostname.

- Universal Service Monitoring now requires a Linux kernel version of 4.14 or greater.


.. _Release Notes_7.40.0_New Features:

New Features
------------

- The Agent RPM package now supports Amazon Linux 2022 and Fedora 30+ without requiring the installation of the additional ``libxcrypt-compat`` system package.

- Add support for CAPI metadata and DCA tags collection in PCF containers.

- Add a username and password dialog window to the Windows Installer

- APM: DogStatsD data can now be proxied through the "/dogstatsd/v1/proxy" endpoint
  over UDP. See https://docs.datadoghq.com/developers/dogstatsd#setup for configuration details.

- Cloud Workload Security now has Agent version constraints for Macros in SECL expressions.

- Added the "helm_values_as_tags" configuration option in the Helm check.  It
  allows users to collect helm values from a Helm release and use them as
  tags to attach to the metrics and events emitted by the Helm check.

- Enable the new DogStatsD no-aggregation pipeline, capable of processing metrics
  with timestamps.
  Set ``dogstatsd_no_aggregation_pipeline`` to ``false`` to disable it.

- Adds ability to identify the interpreter of a script inside a script via the shebang. Example rule would be ``exec.interpreter.file.name == ~"python*"``. This feature is currently limited to one layer of nested script. For example, a python script in a shell script will be caught, but a perl script inside a python script inside a shell script will not be caught.


.. _Release Notes_7.40.0_Enhancement Notes:

Enhancement Notes
-----------------

- JMXFetch now supports ZGC Cycles and ZGC Pauses beans support out of the box.

- Adds new ``aws.lambda.enhanced.post_runtime_duration`` metric for AWS Lambda
  functions. This gauge metric measures the elapsed milliseconds from when
  the function returns the response to when the extensions finishes. This
  includes performing activities like sending telemetry data to a preferred
  destination after the function's response is returned. Note that
  ``aws.lambda.enhanced.duration`` is equivalent to the sum of
  ``aws.lambda.enhanced.runtime_duration`` and
  ``aws.lambda.enhanced.post_runtime_duration``.

- Add the ``flare`` command to the Cloud Foundry ``cluster agent`` to improve support
  experience.

- Add ``CreateContainerError`` and ``InvalidImageName`` to waiting reasons
  for ``kubernetes_state.container.status_report.count.waiting`` in the Kubernetes State Core check.

- [netflow] Ephemeral Port Rollup

- APM: A warning is now logged when the agent is under heavy load.

- APM: The "http.status_code" tag is now supported as a numeric value too when computing APM trace stats. If set as both a string and a numeric value, the numeric value takes precedence and the string value is ignored.

- APM: Add support for cgroup2 via UDS.

- A new config option, ``logs_config.file_wildcard_selection_mode``,
  allows you to configure how log wildcard file matches are
  prioritized if the number of matches exceeds ``logs_config.open_files_limit``.

  The option defaults to ``by_name`` which is the previous behavior.
  The new option is ``by_modification_time`` which prioritizes more recently
  modified files, but using it can result in slower performance compared to using ``by_name``.

- Agents are now built with Go 1.18.7.  This version of Go brings `changes to
  the garbage collection runtime <https://go.dev/doc/go1.18#runtime>`_ that
  may change the Agent's memory usage.  In internal testing, the RSS of Agent
  processes showed a minor increase of a few MiB, while CPU usage remained
  consistent.  Reducing the value of ``GOGC`` as described in the Go
  documentation was effective in reducing the memory usage at a modest cost
  in CPU usage.

- KSM Core check: Add the ``helm_chart`` tag automatically from the standard helm label ``helm.sh/chart``.

- Helm check: Add a ``helm_chart`` tag, equivalent to the standard helm label ``helm.sh/chart`` (see https://helm.sh/docs/chart_best_practices/labels/).

- The OTLP ingest endpoint now supports the same settings and protocol as the OpenTelemetry Collector OTLP receiver v0.60.0. In particular, this drops support for consuming OTLP/JSON v0.15.0 or below payloads.

- Improve CCCache performance on cache miss, significantly reducing
  the number of API calls to the CAPI.

- Add more flags to increase control over the CCCache, such as ``refresh_on_cache_miss``, ``sidecars_tags``,
  and ``isolation_segments_tags`` flags under ``cluster_agent`` properties.

- Windows: Add a config option to control how often the agent refreshes performance counters.

- Introduces an ``unbundle_events`` config to the ``docker`` integration. When
  set to ``true``, Docker events are no longer bundled together by image name,
  and instead generate separate Datadog events.

- Introduces an ``unbundle_events`` config to the ``kubernetes_apiserver``
  integration. When set to ``true``, Kubernetes events are no longer bundled
  together by InvolvedObject, and instead generate separate Datadog events.

- On Windows the Agent now uses high-resolution icon where possible.
  The smaller resolution icons have been resampled for better visibility.


.. _Release Notes_7.40.0_Known Issues:

Known Issues
------------

- APM: OTLP Ingest: resource attributes such as service.name are correctly picked up by spans.
- APM: The "/dogstatsd/v1/proxy" endpoint can only accept a single payload at a time. This will
  be fixed in the v2 endpoint which will split payloads by newline.


.. _Release Notes_7.40.0_Deprecation Notes:

Deprecation Notes
-----------------

- The following Windows Agent container versions are removed: 1909, 2004, and 20H2.


.. _Release Notes_7.40.0_Bug Fixes:

Bug Fixes
---------

- Add the device field to the ``MetricPayload`` to ensure the device
  tag is properly handled by the backend.

- APM: Revised support for tracer single span sampling. See datadog-agent/pull/13461.

- Fixed a problem that could trigger in the containerd collector when
  fetching containers from multiple namespaces.

- Fixed a crash when ``dogstatsd_metrics_stats_enable`` is true

- Fix a bug in Autodiscovery preventing the Agent to correctly schedule checks or logs configurations on newly created PODs during a StatefulSet rollout.

- The included ``aerospike`` Python package is now correctly built against
  the embedded OpenSSL and thus the Aerospike integration can be successfully
  used on RHEL/CentOS.

- Fix configresolver to continue parsing when a null value is found.

- Fixed issue with CPU count on MacOS

- The container CPU limit that is reported by ``docker`` and ``container`` checks on ECS was not defaulting to the task limit when no CPU limit is set at container level.

- Fix potential panic when removing a service that the log agent is currently tailing.

- On SUSE, fixes the permissions declared in the package list of the RPM package.
  This was causing package conflicts between the datadog-agent package and other packages
  with files in ``/usr/lib/systemd/system``.

- Fixed a resource leak in the helm check.

- Fix golang performance counter initialization errors when counters
  are not available during agent/check init time.
  Checks now retry the counter initilization on each interval.

- [snmp] Cache snmp dynamic tags from devices


.. _Release Notes_7.40.0_Other Notes:

Other Notes
-----------

- JMXFetch upgraded to ``0.47.1 https://github.com/DataDog/jmxfetch/releases/0.47.1``

- The ``logs_config.cca_in_ad`` feature flag now defaults to true.  This
  selects updated codepaths in Autodiscovery and the Logs Agent.  No behavior
  change is expected.  Please report any behavior that is "fixed" by setting
  this flag to false.


.. _Release Notes_7.39.1:

7.39.1 / 6.39.1
======

.. _Release Notes_7.39.1_Prelude:

Prelude
-------

Release on: 2022-09-27


.. _Release Notes_7.39.1_Security Notes:

Security Notes
--------------

- Bump ``github.com/open-policy-agent/opa`` to `v0.43.1 <https://github.com/open-policy-agent/opa/releases/tag/v0.43.1>`_ to patch CVE-2022-36085.


.. _Release Notes_7.39.1_Other Notes:

Other Notes
-----------

- Bump embedded Python3 to `3.8.14`.

- Deactivated support of HTTP/2 in all non localhost endpoint used by Datadog Agent and Cluster Agent. (except endpoints)


.. _Release Notes_7.39.0:

7.39.0 / 6.39.0
======

.. _Release Notes_7.39.0_Prelude:

Prelude
-------

Release on: 2022-09-12

- Please refer to the `7.39.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7390>`_ for the list of changes on the Core Checks


.. _Release Notes_7.39.0_Upgrade Notes:

Upgrade Notes
-------------

- Starting with version 6.39.0, Agent 6 is no longer built for macOS.
  Only Agent 7 will be built for macOS going forward. macOS 10.14 and
  above are supported with Agent 7.39.0.


.. _Release Notes_7.39.0_New Features:

New Features
------------

- Add an integrated snmpwalk command to perform a walk for all snmp versions based on the gosnmp library.

- APM: Add two options under the `vector` config prefix to send traces
  to Vector instead of Datadog. Set `vector.traces.enabled` to true.
  Set `vector.traces.url` to point to a Vector endpoint. This overrides
  the main endpoint. Additional endpoints remains fully functional.


.. _Release Notes_7.39.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add the `tagger-list` command to the `process-agent` to ease
  tagging issue investigation.

- Update SNMP traps database with bit enumerations.

- Resolve SNMP trap variables with bit enumerations to their string representation.

- Logs: Support filtering on arbitrary journal log fields

- APM: The trace-agent version string has been made more consistent and is now available in different build environments.

- Delay starting the auto multi-line detection timeout until at
  least one log has been processed.

- The ``helm`` check has new configuration parameters:
  - ``extra_sync_timeout_seconds`` (default 120)
  - ``informers_resync_interval_minutes`` (default 10)

- Improves the `labelsAsTags` feature of the Kubernetes State Metrics core check by performing the transformations of characters ['/' , '-' , '.']
  to underscores ['_'] within the Datadog agent.
  Previously users had to perform these conversions manually in order to discover the labels on their resources.

- The new ``min_tls_version`` configuration parameter allows configuration of
  the minimum TLS version used for connections to the Datadog intake.  This
  replaces the ``force_tls_12`` configuration parameter which only allowed
  the minimum to be set to tlsv1.2.

- The OTLP ingest endpoint now supports the same settings and protocol as the OpenTelemetry Collector OTLP receiver v0.56.0

- 'agent status' command output is now parseable as JSON
  directly from stdout. Before this change, the
  logger front-matter made it hard to parse 'status'
  output directly as JSON.

- Raise the default ``logs_config.open_files_limit`` to ``200`` on
  Windows and macOS. Raised to ``500`` for all other operating systems.

- Support disabling DatadogMetric autogeneration with the
  external_metrics_provider.enable_datadogmetric_autogen configuration option
  (enabled by default).


.. _Release Notes_7.39.0_Deprecation Notes:

Deprecation Notes
-----------------

- APM: The `datadog.trace_agent.trace_writer.bytes_estimated` metric has been removed. It was meant to be a metric used for debugging, without any user added value.

- APM: The trace-agent /info endpoint no longer reports "build_date".

- The ``force_tls_12`` configuration parameter is deprecated, replaced by
  ``min_tls_version``.  If ``min_tls_version`` is not given, but ``force_tls_12``
  is true, then ``min_tls_version`` defaults to tlsv1.2.


.. _Release Notes_7.39.0_Bug Fixes:

Bug Fixes
---------

- Traps variable OIDs that had the index as a suffix are now correctly resolved.

- Agent status command should always log at info level to allow
  full status output regardless of Agent log level settings.

- APM: The "datadog.trace_agent.otlp.spans" metric was incorrectly reporting span count. This release fixes that.

- Fix panic when Agent stops jmxfetch.

- Fixed a bug in Kubernetes Autodiscovery based on pod annotations: The Agent no longer skips valid configurations if other invalid configurations exist.
  Note: This regression was introduced in Agents 7.36.0 and 6.36.0

- Fix a bug in autodiscovery that would not unschedule some checks when check configuration contains secrets.

- Orchestrator check: make sure we don't return labels and annotations with a suffixed `:`

- Fixed a bug in the Docker check that affects the
  `docker.containers.running` metric. It was reporting wrong values in cases
  where multiple containers with different `env`, `service`, `version`, etc.
  tags were using the same image.

- Fixed a deadlock in the DogStatsD when running the capture (`agent dogstatsd-capture`). The Agent now flushes the
  captured messages properly when the capture stops.

- Fix parsing of init_config in AD annotations v2.

- The ``internal_profiling.period`` parameter is now taken into account by the agent.

- Fix duplicated check or logs configurations, targeting dead containers when containers are re-created by Docker Compose.

- Fix concurrent map access issues when using OTLP ingest.

- [orchestrator check] Fixes race condition during check startup.

- The Windows installer will now respect the DDAGENTUSER_PASSWORD option and update the services passwords when the user already exists.

- The KSM Core check now handles cron job schedules with time zones.

- The v5 metadata payload's filesystem information is now more robust against failures in the ``df`` command, such as when a mountpoint is stuck.

- Fixes a disk check issue in the Docker Agent where a disproportionate amount of automount
  request system logs would be produced by the host after each disk check run.

- [epforwarder] Update NetFlow EP forwarder default configs

- The Agent starts faster on a Windows Docker host with many containers running by fetching the containers in parallel.

- On Windows, NPM driver adds support for Receive Segment Coalescing.
  This works around a Windows bug which in some situations causes
  system probe to hang on startup


.. _Release Notes_7.38.2:

7.38.2 / 6.38.2
======

.. _Release Notes_7.38.2_Prelude:

Prelude
-------

Release on: 2022-08-10

- Please refer to the `7.38.2 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7382>`_ for the list of changes on the Core Checks


.. _Release Notes_7.38.2_Bug Fixes:

Bug Fixes
---------

- Fixes a bug making the agent creating a lot of zombie (defunct) processes.
  This bug happened only with the docker images ``7.38.x`` when the containerized agent was launched without ``hostPID: true``.


.. _Release Notes_7.38.1:

7.38.1 / 6.38.1
======

.. _Release Notes_7.38.1_Prelude:

Prelude
-------

Release on: 2022-08-02


.. _Release Notes_7.38.1_Bug Fixes:

Bug Fixes
---------

- Fixes CWS rules with 'process.file.name !=""' expression.


.. _Release Notes_7.38.0:

7.38.0 / 6.38.0
======

.. _Release Notes_7.38.0_Prelude:

Prelude
-------

Release on: 2022-07-25

- Please refer to the `7.38.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7380>`_ for the list of changes on the Core Checks


.. _Release Notes_7.38.0_New Features:

New Features
------------


- Add NetFlow feature to listen to NetFlow traffic and forward them to Datadog.

- The CWS agent now supports filtering events depending on whether they are performed by a thread.
  A process is considered a thread if it's a child process that hasn't executed another program.

- Adds a `diagnose datadog-connectivity` command that displays information about connectivity issues between the Agent and Datadog intake.

- Adds support for tailing modes in the journald logs tailer.

- The CWS agent now supports writing rules on processes termination.

- Add support for new types of CI Visibility payloads to the Trace Agent, so
  features that until now were Agentless-only are available as well when using
  the Agent.


.. _Release Notes_7.38.0_Enhancement Notes:

Enhancement Notes
-----------------

- Tags configured with `DD_TAGS` or `DD_EXTRA_TAGS` in an EKS Fargate environment are now attached to OTLP metrics.

- Add NetFlow static enrichments (TCP flags, IP Protocol, EtherType, and more).

- Report lines matched by auto multiline detection as metrics
  and show on the status page.

- Add a `containerd_exclude_namespaces` configuration option for the Agent to
  ignore containers from specific containerd namespaces.

- The `log_level` of the agent is now appended
  to the flare archive name upon its creation.

- The metrics reported by KSM core now include the tags "kube_app_name",
  "kube_app_instance", and so on, if they're related to a Kubernetes entity
  that has a standard label like "app.kubernetes.io/name",
  "app.kubernetes.io/instance", etc.

- The Kubernetes State Metrics Core check now collects two ingress metrics:
  ``kubernetes_state.ingress.count`` and ``kubernetes_state.ingress.path``.

- Move process chunking code to util package to avoid cycle import when using it in orchestrator check.

- APM: Add support for PostgreSQL JSON operators in the SQL obfuscate package.

- The OTLP ingest endpoint now supports the same settings and protocol as the OpenTelemetry Collector OTLP receiver v0.54.0 (OTLP v0.18.0).

- The Agent now embeds Python-3.8.13, an upgrade from
  Python-3.8.11.

- APM: Updated Rare Sampler default configuration values to sample traces more uniformly across environments and services.

- The OTLP ingest endpoint now supports Exponential Histograms with delta aggregation temporality.

- The Windows installer now supports grouped Managed Service Accounts.

- Enable https monitoring on arm64 with kernel >= 5.5.0.

- Add ``otlp_config.debug.loglevel`` to determine log level when the OTLP Agent receives metrics/traces for debugging use cases.


.. _Release Notes_7.38.0_Deprecation Notes:

Deprecation Notes
-----------------

- Deprecate``otlp_config.metrics.instrumentation_library_metadata_as_tags`` in
  in favor of ``otlp_config.metrics.instrumentation_scope_metadata_as_tags``.


.. _Release Notes_7.38.0_Bug Fixes:

Bug Fixes
---------

- When ``enable_payloads.series`` or ``enable_payloads.sketches`` are set to
  false, don't log the error ``Cannot append a metric in a closed buffered channel``.

- Restrict permissions for the entrypoint executables of the Dockerfiles.

- Revert `docker.mem.in_use` calculation to use RSS Memory instead of total memory.

- Add missing telemetry metrics for HTTP log bytes sent.

- Fix `panic` in `container`, `containerd`, and `docker` when container stats are temporarily not available

- Fix prometheus check Metrics parsing by not enforcing a list of strings.

- Fix potential deadlock when shutting down an Agent with a log TCP listener.

- APM: Fixed trace rare sampler's oversampling behavior. With this fix, the rare sampler will sample rare traces more accurately.

- Fix journald byte count on the status page.

- APM: Fixes an issue where certain (#> and #>>) PostgreSQL JSON operators were
  being interpreted as comments and removed by the obfuscate package.

- Scrubs HTTP Bearer tokens out of log output

- Fixed the triggered "svType != tvType; key=containerd_namespace, st=[]interface
  {}, tt=[]string, sv=[], tv=[]" error when using a secret backend
  reader.

- Fixed an issue that made the container check to show an error in the "agent
  status" output when it was working properly but there were no containers
  deployed.


.. _Release Notes_7.37.1:

7.37.1 / 6.37.1
======

.. _Release Notes_7.37.1_Prelude:

Prelude
-------

Release on: 2022-06-28


.. _Release Notes_7.37.1_Bug Fixes:

Bug Fixes
---------

- Fixes issue where proxy config was ignored by the trace-agent.


.. _Release Notes_7.37.0:

7.37.0 / 6.37.0
======

.. _Release Notes_7.37.0_Prelude:

Prelude
-------

Release on: 2022-06-27

- Please refer to the `7.37.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7370>`_ for the list of changes on the Core Checks


.. _Release Notes_7.37.0_Upgrade Notes:

Upgrade Notes
-------------

- OTLP ingest: Support for the deprecated ``experimental.otlp`` section and the ``DD_OTLP_GRPC_PORT`` and ``DD_OTLP_HTTP_PORT`` environment variables has been removed. Use the ``otlp_config`` section or the ``DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT`` and ``DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT`` environment variables instead.

- OTLP: Deprecated settings ``otlp_config.metrics.report_quantiles`` and ``otlp_config.metrics.send_monotonic_counter`` have been removed in favor of ``otlp_config.metrics.summaries.mode`` and ``otlp_config.metrics.sums.cumulative_monotonic_mode`` respectively.


.. _Release Notes_7.37.0_New Features:

New Features
------------

- Adds User-level service unit filtering support for Journald log collection via ``include_user_units`` and ``exclude_user_units``.

- A wildcard (`*`) can be used in either `exclude_units` or `exclude_user_units` if only a particular type of Journald log is desired.

- A new `troubleshooting` section has been added to the Agent CLI. This section will hold helpers to understand the
  Agent behavior. For now, the section only has two command to print the different metadata payloads sent by the Agent
  (`v5` and `inventory`).

- APM: Incoming OTLP traces are now allowed to set their own sampling priority.

- Enable NPM NAT gateway lookup by default.

- Partial support of IPv6 on EKS clusters
  * Fix the kubelet client when the IP of the host is IPv6.
  * Fix the substitution of `%%host%%` patterns inside the auto-discovery annotations:
    If the concerned pod has an IPv6 and the `%%host%%` pattern appears inside an URL context, then the IPv6 is surrounded by square brackets.

- OTLP ingest now supports the same settings and protocol version as the OpenTelemetry Collector OTLP receiver v0.50.0.

- The Cloud Workload Security agent can now monitor and evaluate rules on bind syscall.

- [corechecks/snmp] add scale factor option to metric configurations

- Evaluate ``memory.usage`` metrics based on collected metrics.


.. _Release Notes_7.37.0_Enhancement Notes:

Enhancement Notes
-----------------

- APM: ``DD_APM_FILTER_TAGS_REQUIRE`` and ``DD_APM_FILTER_TAGS_REJECT`` can now be a literal JSON array.
  e.g. ``["someKey:someValue"]`` This allows for matching tag values with the space character in them.

- SNMP Traps are now sent to a dedicated intake via the epforwarder.

- Update SNMP traps database to include integer enumerations.

- The Agent now supports a single ``com.datadoghq.ad.checks`` label in Docker,
  containerd, and Podman containers. It merges the contents of the existing
  ``check_names``, ``init_configs`` (now optional), and ``instances`` annotations
  into a single JSON value.

- Add a new Agent telemetry metric ``autodiscovery_poll_duration`` (histogram)
  to monitor configuration poll duration in Autodiscovery.

- APM: Added ``/config/set`` endpoint in trace-agent to change configuration settings during runtime.
  Supports changing log level(log_level).

- APM: When the X-Datadog-Trace-Count contains an invalid value, an error will be issued.

- Upgrade to Docker client 20.10, reducing the duration of `docker` check on Windows (requires Docker >= 20.10 on the host).

- The Agent maintains scheduled cluster and endpoint checks when the Cluster Agent is unavailable.

- The Cluster Agent followers now forward queries to the Cluster Agent leaders themselves. This allows a reduction in the overall number of connections to the Cluster Agent and better spreads the load between leader and forwarders.

- The ``kube_namespace`` tag is now included in all metrics,
  events, and service checks generated by the Helm check.

- Include `install_info` to `version-history.json`

- Allow nightly builds install on non-prod repos

- Add a ``kubernetes_node_annotations_as_tags`` parameter to use Kubernetes node annotations as host tags.

- Add more detailed logging around leadership status failures.

- Move the experimental SNMP Traps Listener configuration under ``network_devices``.

- Add support for the DNS Monitoring feature of NPM to Linux kernels older than 4.1.

- Adds ``segment_name`` and ``segment_id`` tags to PCF containers that belong to an isolation segment.

- Make logs agent ``additional_endpoints`` reliable by default.
  This can be disabled by setting ``is_reliable: false``
  on the additional endpoint.

- On Windows, if a ``datadog.yaml`` file is found during an installation or
  upgrade, the dialogs collecting the API Key and Site are skipped.

- Resolve SNMP trap variables with integer enumerations to their string representation.

- [corechecks/snmp] Add profile ``static_tags`` config

- Report telemetry metrics about the retry queue capacity: ``datadog.agent.retry_queue_duration.capacity_secs``, ``datadog.agent.retry_queue_duration.bytes_per_sec`` and ``datadog.agent.retry_queue_duration.capacity_bytes``

- Updated cloud providers to add the Instance ID as a host alias
  for EC2 instances, matching what other cloud providers do. This
  should help with correctly identifying hosts where the customer
  has changed the hostname to be different from the Instance ID.

- NTP check: Include ``/etc/ntpd.conf`` and ``/etc/openntpd/ntpd.conf`` for ``use_local_defined_servers``.

- Kubernetes pod with short-lived containers do not have log lines duplicated with both container tags (the stopped one and the running one) when logs are collected.
  This feature is enabled by default, set ``logs_config.validate_pod_container_id`` to ``false`` to disable it.


.. _Release Notes_7.37.0_Security Notes:

Security Notes
--------------

- The Agent is built with Go 1.17.11.


.. _Release Notes_7.37.0_Bug Fixes:

Bug Fixes
---------

- Updates defaults for the port and binding host of the experimental traps listener.

- APM: The Agent is now performing rare span detection on all spans,
  as opposed to only dropped spans. This change will slightly reduce
  the number of rare spans kept unnecessarily.

- APM OTLP: This change ensures that the ingest now standardizes certain attribute keys to their correct Datadog tag counter parts, such as: container tags, "operation.name", "service.name", etc.

- APM: Fix a bug where the APM section of the GUI would not show up in older Internet Explorer versions on Windows.

- Support dynamic Auth Tokens in Kubernetes v1.22+ (Bound Service Account Token Volume).

- The "%%host%%" autodiscovery tag now works properly when using containerd, but only on Linux and when using IP v4 addresses.

- Enhanced the coverage of pause-containers filtering on Containerd.

- APM: Fix the loss of trace metric container information when large payloads need to be split.

- Fix `cri` check producing no metrics when running on `OpenShift / cri-o`.

- Fix missing health status from Docker containers in Live Container View.

- Fix Agent startup failure when running as a non-privileged user (for instance, when running on OpenShift with ``restricted`` SCC).

- Fix missing container metrics (container, containerd checks and live container view) on AWS Bottlerocket.

- APM: Fixed an issue where "CPU threshold exceeded" logs would show the wrong user CPU usage by a factor of 100.

- Ensures that when ``kubernetes_namespace_labels_as_tags`` is set, the namespace labels are always attached to metrics and logs, even when the pod is not ready yet.

- Add missing support for UDPv6 receive path to NPM.

- The ``agent workload-list --verbose`` command and the ``workload-list.log`` file in the flare
  do not show containers' environment variables anymore. Except for ``DD_SERVICE``, ``DD_ENV`` and ``DD_VERSION``.

- Fixed a potential deadlock in the Python check runner during agent shutdown.

- Fixes issue where trace-agent would not report any version info.

- The DCA and the cluster runners no longer write warning logs to `/tmp`.

- Fixes an issue where the Agent would panic when trying to inspect Docker
  containers while the Docker daemon was unavailable or taking too long to
  respond.


.. _Release Notes_7.37.0_Other Notes:

Other Notes
-----------

- Exclude teradata on Mac agents.


.. _Release Notes_7.36.1:

7.36.1 / 6.36.1
======

.. _Release Notes_7.36.1_Prelude:

Prelude
-------

Release on: 2022-05-31

- Please refer to the `7.36.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7361>`_ for the list of changes on the Core Checks


.. _Release Notes_7.36.1_Bug Fixes:

Bug Fixes
---------

- Fixes issue where proxy config was ignored by the trace-agent.

- This fixes a regression introduced in ``7.36.0`` where some logs sources attached to a container/pod would not be
  unscheduled on container/pod stop if multiple logs configs were attached to the container/pod.
  This could lead to duplicate log entries being created on container/pod restart as there would
  be more than one tailer tailing the targeted source.


.. _Release Notes_7.36.0:

7.36.0 / 6.36.0
======

.. _Release Notes_7.36.0_Prelude:

Prelude
-------

Release on: 2022-05-24

- Please refer to the `7.36.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7360>`_ for the list of changes on the Core Checks


.. _Release Notes_7.36.0_Upgrade Notes:

Upgrade Notes
-------------

- Debian packages are now built on Debian 8. Newly built DEBs are supported
  on Debian >= 8 and Ubuntu >= 14.

- The OTLP endpoint will no longer enable the legacy OTLP/HTTP endpoint ``0.0.0.0:55681`` by default. To keep using the legacy endpoint, explicitly declare it via the ``otlp_config.receiver.protocols.http.endpoint`` configuration setting or its associated environment variable, ``DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT``.

- Package signing keys were rotated:

  * DEB packages are now signed with key ``AD9589B7``, a signing subkey of key `F14F620E <https://keys.datadoghq.com/DATADOG_APT_KEY_F14F620E.public>`_
  * RPM packages are now signed with key `FD4BF915 <https://keys.datadoghq.com/DATADOG_RPM_KEY_FD4BF915.public>`_


.. _Release Notes_7.36.0_New Features:

New Features
------------

- Adding support for IBM cloud. The agent will now detect that we're running on IBM cloud and collect host aliases
  (vm name and ID).

- Added event collection in the Helm check. The feature is disabled by default. To enable it, set the ``collect_events`` option to true.

- Adds a service check for the Helm check. The check fails for a release when its latest revision is in "failed" state.

- Adds a ``kube_qos`` (quality of service) tag to metrics associated with
  kubernetes pods and their containers.

- CWS can now track network devices creation and load TC classifiers dynamically.

- CWS can now track network namespaces.

- The DNS event type was added to CWS.

- The OTLP ingest endpoint is now considered GA for metrics.

.. _Release Notes_7.36.0_Enhancement Notes:

Enhancement Notes
-----------------

- Traps OIDs are now resolved to names using user-provided 'traps db' files in ``snmp.d/traps_db/``.

- The Agent now supports a single ``ad.datadoghq.com/$IDENTIFIER.checks``
  annotation in Kubernetes Pods and Services to configure Autodiscovery
  checks. It merges the contents of the existing "check_names",
  ``init_configs`` (now optional), and ``instances`` annotations into a single
  JSON value.

- ``DD_URL`` environment variable can now be used to set the Datadog intake URL just like ``DD_DD_URL``.
  If both ``DD_DD_URL`` and `DD_URL` are set, ``DD_DD_URL`` will be used to avoid breaking change.

- Added a ``process-agent version`` command, and made the output mimic the core agent.

- Windows: Add Datadog registry to Flare.

- Add ``--service`` flag to ``stream-logs`` command to filter
  streamed logs in detail.

- Support a simple date pattern for automatic multiline detection

- APM: The OTLP ingest stringification of non-standard Datadog values such as Arrays and KeyValues is now consistent with OpenTelemetry attribute stringification.

- APM: Connections to upload profiles to the Datadog intake are now closed
  after 47 seconds of idleness. Common tracer setups send one profile every
  60 seconds, which coincides with the intake's connection timeout and would
  occasionally lead to errors.

- The Cluster Agent now exposes a new metric ``cluster_checks_configs_info``.
  It exposes the node and the check ID as tags.

- KSM core check: add a new ``kubernetes_state.cronjob.complete``
  service check that returns the status of the most recent job for
  a cronjob.

- Retry more HTTP status codes for the logs agent HTTP destination.

- ``COPYRIGHT-3rdparty.csv`` now contains each copyright statement exactly as it is shown on the original component.

- Adds ``sidecar_present`` and ``sidecar_count`` tags on Cloud Foundry containers
  that run apps with sidecar processes.

- Agent flare now includes output from the ``process`` and ``container`` checks.

- Add the ``--cfgpath`` parameter in the Process Agent replacing ``--config``.

- Add the ``check`` subcommand in the Process Agent replacing ``--check`` (``-check``).
  Only warn once if the ``-version`` flag is used.

- Adds human readable output of process and container data in the ``check`` command
  for the Process Agent.

- The Agent flare command now collects Process Agent performance profile data in the flare bundle when the ``--profile`` flag is used.


.. _Release Notes_7.36.0_Deprecation Notes:

Deprecation Notes
-----------------

- Deprecated ``process-agent --vesion`` in favor of ``process-agent version``.

- The logs configuration ``use_http`` and ``use_tcp`` flags have been deprecated in favor of ``force_use_http`` and ``force_use_tcp``.

- OTLP ingest: ``metrics.send_monotonic_counter`` has been deprecated in favor of ``metrics.sums.cumulative_monotonic_mode``. ``metrics.send_monotonic_counter`` will be removed in v7.37.

- OTLP ingest: ``metrics.report_quantiles`` has been deprecated in favor of ``metrics.summaries.mode``. ``metrics.report_quantiles`` will be removed in v7.37 / v6.37.

- Remove the unused ``--ddconfig`` (``-ddconfig``) parameter.
  Deprecate the ``--config`` (``-config``) parameter (show warning on usage).

- Deprecate the ``--check`` (``-check``) parameter (show warning on usage).


.. _Release Notes_7.36.0_Bug Fixes:

Bug Fixes
---------

- Bump GoSNMP to fix incomplete support of SNMP v3 INFORMs.

- APM: OTLP: Fixes an issue where attributes from different spans were merged leading to spans containing incorrect attributes.

- APM: OTLP: Fixed an inconsistency where the error message was left empty in cases where the "exception" event was not found. Now, the span status message is used as a fallback.

- Fixes an issue where some data coming from the Agent when running in ECS
  Fargate did not have ``task_*``, ``ecs_cluster_name``, ``region``, and
  ``availability_zone`` tags.

- Collect the "0" value for resourceRequirements if it has been set

- Fix a bug introduced in 7.33 that could prevent auto-discovery variable ``%%port_<name>%%`` to not be resolved properly.

- Fix a panic in the Docker check when a failure happens early (when listing containers)

- Fix missing ``docker.memory.limit`` (and ``docker.memory.in_use``) on Windows

- Fixes a conflict preventing NPM/USM and the TCP Queue Length check from being enabled at the same time.

- Fix permission of "/readsecret.sh" script in the agent Dockerfile when
  executing with dd-agent user (for cluster check runners)

- For Windows, fixes problem in upgrade wherein NPM driver is not automatically started by system probe.

- Fix Gohai not being able to fetch network information when running on a non-English windows (when the output of
  commands like ``ipconfig`` were not in English). ``gohai`` no longer relies on system commands but uses Golang ``net`` package
  instead (same as Linux hosts).
  This bug had the side effect of preventing network monitoring data to be linked back to the host.

- Time-based metrics (for example, ``kubernetes_state.pod.age``, ``kubernetes_state.pod.uptime``) are now comparable in the Kubernetes state core check.

- Fix a risk of panic when multiple KSM Core check instances run concurrently.

- For Windows, includes NPM driver 1.3.2, which has a fix for a BSOD on system probe shutdown.

- Adds new ``--json`` flag to ``check``. ``process-agent check --json`` now outputs valid json.

- On Windows, includes NPM driver update which fixes performance
  problem when host is under high connection load.

- Previously, the Agent could not log the start or end of a check properly after the first five check runs. The Agent now can log the start and end of a check correctly.


.. _Release Notes_7.36.0_Other Notes:

Other Notes
-----------

- Include pre-generated trap db file in the ``conf.d/snmp.d/traps_db/`` folder.

- Gohai dependency has been upgraded. This brings a newer version of gopsutil and a fix when fetching network
  information in non-english Windows (see ``fixes`` section).


.. _Release Notes_7.35.2:

7.35.2 / 6.35.2
======

.. _Release Notes_7.35.2_Prelude:

Prelude
-------

Release on: 2022-05-05

.. _Release Notes_7.35.2_Bug Fixes:

Bug Fixes
---------

- Fix a regression impacting CSPM metering

.. _Release Notes_7.35.1:

7.35.1 / 6.35.1
======

.. _Release Notes_7.35.1_Prelude:

Prelude
-------

Release on: 2022-04-12


.. _Release Notes_7.35.1_Bug Fixes:

Bug Fixes
---------

- The weak dependency of datadog-agent, datadog-iot-agent and dogstatsd deb
  packages on the datadog-signing-keys package has been fixed to ensure
  proper upgrade to version 1:1.1.0.


.. _Release Notes_7.35.0:

7.35.0 / 6.35.0
======

.. _Release Notes_7.35.0_Prelude:

Prelude
-------

Release on: 2022-04-07

- Please refer to the `7.35.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7350>`_ for the list of changes on the Core Checks


.. _Release Notes_7.35.0_Upgrade Notes:

Upgrade Notes
-------------

- Agent, Dogstatsd and IOT Agent RPMs now have proper preinstall dependencies.
  On AlmaLinux, Amazon Linux, CentOS, Fedora, RHEL and Rocky Linux, these are:

  - ``coreutils`` (provided by package ``coreutils-single`` on certain platforms)
  - ``grep``
  - ``glibc-common``
  - ``shadow-utils``

  On OpenSUSE and SUSE, these are:

  - ``coreutils``
  - ``grep``
  - ``glibc``
  - ``shadow``

- APM Breaking change: The `default head based sampling mechanism <https://docs.datadoghq.com/tracing/trace_ingestion/mechanisms?tab=environmentvariables#head-based-default-mechanism>`_
  settings `apm_config.max_traces_per_second` or `DD_APM_MAX_TPS`, when set to 0, will be sending
  0% of traces to Datadog, instead of 100% in previous Agent versions.

- The OTLP ingest endpoint is now considered stable for traces.
  Its configuration is located in the top-level `otlp_config section <https://github.com/DataDog/datadog-agent/blob/7.35.0/pkg/config/config_template.yaml#L2915-L2918>`_.

  Support for the deprecated ``experimental.otlp`` section and the ``DD_OTLP_GRPC_PORT`` and ``DD_OTLP_HTTP_PORT``
  environment variables will be removed in Agent 7.37. Use the ``otlp_config`` section or the
  ``DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT`` and ``DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT``
  environment variables instead.

- macOS 10.12 support has been removed. Only macOS 10.13 and later are now supported.


.. _Release Notes_7.35.0_New Features:

New Features
------------

- The Cloud Workload Security agent can now monitor and evaluate rules on signals (kill syscall).

- CWS allows to write SECL rule on environment variable values.

- The security Agent now offers a command to directly download the policy file from the API.

- CWS: Policy can now define macros with items specified as a YAML list
  instead of a SECL expression, as:::

    - my_macro:
      values:
        - value1
        - value2

  In addition, macros and rules can now be updated in later loaded policies
  (``default.policy`` is loaded first, the other policies in the folder are loaded
  in alphabetical order).

  The previous macro can be modified with:::

    - my_macro:
      combine: merge
      values:
        - value3

  It can also be overriden with:::

    - my_macro:
      combine: override
      values:
        - my-single-value

  Rules can now also be disabled with:::

    - my_rule:
      disabled: true

- Cloud Workload Security now works on Google's Container Optimized OS LTS versions, starting
  from v81.

- CWS: Allow setting variables to store states through rule actions.
  Action rules can now be defined as follows:::

    - id: my_rule
      expression: ...
      actions:
        - set:
            name: my_boolean_variable
            value: true
        - set:
            name: my_string_variable
            value: a string
        - set:
            name: my_other_variable
            field: process.file.name

  These actions will be executed when the rule is triggered by an event.
  Right now, only ``set`` actions can be defined.
  ``name`` is the name of the variable that will be set by the actions.
  The value for the variable can be specified by using:

  - ``value`` for a predefined value
    (strings, integers, booleans, array of strings and array of integers are currently supported).
  - ``field`` for the value of an event field.

  Variable arrays can be modified by specifying ``append: true``.

  Variables can be reused in rule expressions like a regular variable:::

    - id: my_other_rule
      expression: |-
        open.file.path == ${my_other_variable}

  By default, variables are global. They can be bounded to a specific process by using the ``process``
  scope as follows:::

    - set:
        name: my_scoped_variable
        scope: process
        value: true

  The variable can be referenced in other expressions as ``${process.my_scoped_variable}``. When the process dies, the
  variable with be automatically freed.

- Configuration ``process_config.enabled`` is now split into two settings: ``process_config.process_collection.enabled`` and ``process_config.container_collection.enabled``. This will allow better control over the process Agent.
  ``process_config.enabled`` now translates to these new settings:

  * ``process_config.enabled=true``: ``process_config.process_collection.enabled=true``
  * ``process_config.enabled=false``: ``process_config.container_collection.enabled=true`` and ``process_config.process_collection.enabled=false``
  * ``process_config.enabled=disabled``: ``process_config.container_collection.enabled=false`` and ``process_config.process_collection.enabled=false``

- Expose additional CloudFoundry metadata in the DCA API that the
  PCF firehose nozzles can use to reduce the load on the CC API.

- Added new "Helm" cluster check that collects information about the Helm releases deployed in the cluster.

- Add the ``process_agent_runtime_config_dump.yaml`` file to the core Agent flare with ``process-agent`` runtime settings.

- Add ``process-agent status`` output to the core Agent status command.

- Added new ``process-agent status`` command to help with troubleshooting and for better consistency with the core Agent. This command is intended to eventually replace `process-agent --info`.

- CWS rules can now be written on kernel module loading and deletion events.

- The splice event type was added to CWS. It can be used to detect the Dirty Pipe vulnerability.

- Add two options under a new config prefix to send logs
  to Vector instead of Datadog. ``vector.logs.enabled``
  must be set to true, along with ``vector.logs.url`` that
  should be set to point to a Vector configured accordingly.
  This overrides the main endpoints, additional endpoints
  remains fully functional.

- Adds new Windows system check, winkmem.  This check reports the top users
  of paged and non-paged memory in the windows kernel.


.. _Release Notes_7.35.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add support for the device_namespace tag in SNMP Traps.

- SNMP Trap Listener now also supports protocol versions 1 and 3 on top of the existing v2 support.

- The cluster agent has an external metrics provider feature to allow using Datadog queries in Kubernetes HorizontalPodAutoscalers.
  It sometimes faces issues like:

    2022-01-01 01:01:01 UTC | CLUSTER | ERROR | (pkg/util/kubernetes/autoscalers/datadogexternal.go:79 in queryDatadogExternal) | Error while executing metric query ... truncated... API returned error: Query timed out

  To mitigate this problem, use the new ``external_metrics_provider.chunk_size`` parameter to reduce the number of queries that are batched by the Agent and sent together to Datadog.

- Added a new implementation of the `containerd` check based on the `container` check. Several metrics are not emitted anymore: `containerd.mem.current.max`, `containerd.mem.kernel.limit`, `containerd.mem.kernel.max`, `containerd.mem.kernel.failcnt`, `containerd.mem.swap.limit`, `containerd.mem.swap.max`, `containerd.mem.swap.failcnt`, `containerd.hugetlb.max`, `containerd.hugetlb.failcount`, `containerd.hugetlb.usage`, `containerd.mem.rsshuge`, `containerd.mem.dirty`, `containerd.blkio.merged_recursive`, `containerd.blkio.queued_recursive`, `containerd.blkio.sectors_recursive`, `containerd.blkio.service_recursive_bytes`, `containerd.blkio.time_recursive`, `containerd.blkio.serviced_recursive`, `containerd.blkio.wait_time_recursive`, `containerd.blkio.service_time_recursive`.
  The `containerd.image.size` now reports all images present on the host, container tags are removed.

- Migrate the cri check to generic check infrastructure. No changes expected in metrics.

- Tags configured with `DD_TAGS` or `DD_EXTRA_TAGS` in an ECS Fargate or EKS Fargate environment are now attached to Dogstatsd metrics.

- Added a new implementation of the `docker` check based on the `container` check. Metrics produced do not change. Added the capability to run the `docker` check on Linux without access to `/sys` or `/proc`, although with a limited number of metrics.

- The DogstatsD protocol now supports a new field that contains the client's container ID.
  This allows enriching DogstatsD metrics with container tags.

- When ``ec2_collect_tags`` is enabled, the Agent now attempts to fetch data
  from the instance metadata service, falling back to the existing
  EC2-API-based method of fetching tags.  Support for tags in the instance
  metadata service is an opt-in EC2 feature, so this functionality will
  not work automatically.

- Add support for ECS metadata v4 API
  https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html

- Agents are now built with Go 1.17.6.

- On ECS Fargate and EKS Fargate, Agent-configured tags (``DD_TAGS``/``DD_EXTRA_TAGS``)
  are now applied to all integration-collected metrics.

- Logs from JMXFetch will now be included in the Agent logfile, regardless
  of the ``log_level`` setting of the Agent.

- Addition of two knobs to configure JMXFetch statsd client:

  * ``jmx_statsd_client_queue_size`` to set the client queue size.
  * ``jmx_statsd_telemetry_enabled`` to enable the client telemetry.

- KSMCore `node.ready` service check now reports `warning`
  instead of `unknown` when a node enters an unknown state.

- Added `DD_PROCESS_CONFIG_PROCESS_DD_URL` and `DD_PROCESS_AGENT_PROCESS_DD_URL` environment variables

- Added `DD_PROCESS_CONFIG_ADDITIONAL_ENDPOINTS` and `DD_PROCESS_AGENT_ADDITIONAL_ENDPOINTS` environment variables

- Automatically extract the ``org.opencontainers.image.source`` container label into the ``git.repository_url`` tag.

- The experimental OTLP ingest endpoint now supports the same settings as the OpenTelemetry Collector OTLP receiver v0.43.1.

- The OTLP ingest endpoint now supports the same settings as the OpenTelemetry Collector OTLP receiver v0.44.0.

- The OTLP ingest endpoint can now be configured through environment variables.

- The OTLP ingest endpoint now always maps conventional metric resource-level attributes to metric tags.

- OTLP ingest: the ``k8s.pod.uid`` and ``container.id`` semantic conventions
  are now used for enriching tags in OTLP metrics.

- Add the ``DD_PROCESS_CONFIG_MAX_PER_MESSAGE`` env variable to set the ``process_config.max_per_message``.
  Add the ``DD_PROCESS_CONFIG_MAX_CTR_PROCS_PER_MESSAGE`` env variable to set the ``process_config.max_ctr_procs_per_message``.

- Add the ``DD_PROCESS_CONFIG_EXPVAR_PORT`` and ``DD_PROCESS_AGENT_EXPVAR_PORT`` env variables to set the ``process_config.expvar_port``.
  Add the ``DD_PROCESS_CONFIG_CMD_PORT`` env variable to set the ``process_config.cmd_port``.

- Add the ``DD_PROCESS_CONFIG_INTERNAL_PROFILING_ENABLED`` env variable to set the ``process_config.internal_profiling.enabled``.

- Add the `DD_PROCESS_CONFIG_SCRUB_ARGS` and `DD_PROCESS_AGENT_SCRUB_ARGS` env variables to set the `process_config.scrub_args`.
  Add the `DD_PROCESS_CONFIG_CUSTOM_SENSITIVE_WORDS` and `DD_PROCESS_AGENT_CUSTOM_SENSITIVE_WORDS` env variables to set the `process_config.custom_sensitive_words`.
  Add the `DD_PROCESS_CONFIG_STRIP_PROC_ARGUMENTS` and `DD_PROCESS_AGENT_STRIP_PROC_ARGUMENTS` env variables to set the `process_config.strip_proc_arguments`.

- Added `DD_PROCESS_CONFIG_WINDOWS_USE_PERF_COUNTERS` and `DD_PROCESS_AGENT_WINDOWS_USE_PERF_COUNTERS` environment variables

- Add the ``DD_PROCESS_CONFIG_QUEUE_SIZE`` and ``DD_PROCESS_AGENT_QUEUE_SIZE`` env variables to set the ``process_config.queue_size``.
  Add the ``DD_PROCESS_CONFIG_RT_QUEUE_SIZE`` and ``DD_PROCESS_AGENT_RT_QUEUE_SIZE`` env variables to set the ``process_config.rt_queue_size``.
  Add the ``DD_PROCESS_CONFIG_PROCESS_QUEUE_BYTES`` and ``DD_PROCESS_AGENT_PROCESS_QUEUE_BYTES`` env variables to set the ``process_config.process_queue_bytes``.

- Changes process payload chunking in the process Agent to take into account
  the size of process details such as CLI and user name.
  Adds the process_config.max_message_bytes setting for the target max (uncompressed) payload size.

- When ``ec2_collect_tags`` is configured, the Agent retries API calls to gather EC2 tags before giving up.

- Retry HTTP transaction when the HTTP status code is 404 (Not found).

- Validate SNMP namespace to ensure it respects length and illegal character rules.

- Include `/etc/chrony.conf` for `use_local_defined_servers`.


.. _Release Notes_7.35.0_Deprecation Notes:

Deprecation Notes
-----------------

- The security Agent commands ``check-policies`` and ``reload`` are deprecated.
  Use ``runtime policy check`` and ``runtime policy reload`` respectively instead.

- Configuration ``process_config.enabled`` is now deprecated.  Use ``process_config.process_collection.enabled`` and ``process_config.container_collection.enabled`` settings instead to control container and process collection in the process Agent.

- Removed ``API_KEY`` environment variable from the process agent. Use ``DD_API_KEY`` instead

- Removes the ``DD_PROCESS_AGENT_CONTAINER_SOURCE`` environment variable from the Process Agent. The list of container sources now entirely depends on the activated features.

- Removed unused ``process_config.windows.args_refresh_interval`` config setting

- Removed unused ``process_config.windows.add_new_args`` config setting

- Removes the ``process_config.max_ctr_procs_per_message`` setting.


.. _Release Notes_7.35.0_Bug Fixes:

Bug Fixes
---------

- APM: OTLP: Fixes an issue where attributes from different spans were merged leading to spans containing incorrect attributes.

- APM: Fixed an issue which caused a panic when receiving OTLP traces with invalid data (specifically duplicate SpanIDs).

- Silence the misleading error message
  ``No valid api key found, reporting the forwarder as unhealthy``
  from the output of the ``agent check`` command.

- Fixed a deadlock in the Logs Agent.

- Exclude filters no longer apply to empty container names, images, or namespaces.

- Fix CPU limit calculation for Windows containers.

- Fix a rare panic in Gohai when collecting the system's Python version.

- For Windows, includes NPM driver 1.3.2, which has a fix for a BSOD on system probe shutdown.

- OTLP ingest now uses the exact sum and count values from OTLP Histograms when generating Datadog distributions.


.. _Release Notes_7.35.0_Other Notes:

Other Notes
-----------

- JMXFetch upgraded to `0.46.0` https://github.com/DataDog/jmxfetch/releases/0.46.0


.. _Release Notes_7.34.0:

7.34.0 / 6.34.0
======

.. _Release Notes_7.34.0_Prelude:

Prelude
-------

Release on: 2022-03-02

- Please refer to the `7.34.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7340>`_ for the list of changes on the Core Checks


.. _Release Notes_7.34.0_Upgrade Notes:

Upgrade Notes
-------------

- CWS uses `**` for subfolder matching instead of `*`.
  Previously, `*` was used to match files and subfolders. With this
  release, `*` will match only files and folders at the same level. Use`**`
  at the end of a path to match files and subfolders. `**` must be
  used at the end of the path. For example, the rule `open.file.path == "/etc/*"`
  has to be converted to `open.file.path == "/etc/**"`.

- `additional_endpoints` in the `logs_config` now uses the same compression
  configuration as the main endpoint when sending to HTTP destinations. Agents
  that relied on using different compression settings for `additional_endpoints`
  may need to be reconfigured.


.. _Release Notes_7.34.0_New Features:

New Features
------------

- Autodiscovery of integrations now works with Podman containers. The minimum
  Podman version supported is 3.0.0.

- Cloud provider detection now support Oracle Cloud. This includes cloud provider detection, host aliases and NTP
  servers.

- APM: Add proxy endpoint to allow Instrumentation Libraries to submit telemetry data.

- CWS now allows to write SECL rule based on process ancestor args.

- CWS now exposes the first argument of exec event. Usually the
  name of the executed program.

- Add a new `runtime reload` command to the `security-agent`
  to dynamically reload CWS policies.

- Enables process discovery check to run by default in the process agent.
  Process discovery is a lightweight process metadata collection check enabling
  users to see recommendations for integrations running in their environments.

- APM: Adds a new endpoint to the Datadog Agent to forward pipeline stats to the Datadog backend.

- The Cloud Workload Security agent can now monitor and evaluate rules on mmap, mprotect and ptrace.

- Add support for Shift JIS (Japanese) encoding.
  It should be manually enabled in a log configuration using
  ``encoding: shift-jis``.

- Extend SNMP profile syntax to support metadata definitions

- When running inside a container with the host `/etc` folder mounted to `/host/etc`, the agent will now report the
  distro informations of the host instead of the one from the container.

- Added telemetry for the workloadmeta store.


.. _Release Notes_7.34.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add Autodiscovery telemetry.

- APM: Add the option to collect SQL comments and commands during obfuscation.

- Adds the process_config.disable_realtime_checks config setting in the process
  Agent allowing users to disable realtime process and container checks. Note:
  This prevents refresh of stats in the Live Processes and Live Containers pages
  for processes and containers reported by the Agent.

- [corechecks/snmp] Add additional metadata fields

- Reduce the memory usage when flushing series.

- Specifying ``auto_multi_line_detection: false`` in an integration's
  ``logs_config`` will now disable detection for that integration, even if
  detection is enabled globally.

- Make ``agent checkconfig`` an alias of ``agent configcheck``

- Added possibility to watch all the namespaces when running on containerd
  outside Kubernetes. By default, the agent will report events and metrics
  from all the namespaces. In order to select a specific one, please set the
  `containerd_namespace` option.

- The container check now works for containers managed by runtimes that
  implement the CRI interface such as CRI-O.

- ``cri.*`` and ``container.*`` metrics can now be collected from the CRI API
  on Windows.

- When using ``site: ddog-gov.com``, the agent now uses Agent-version-based
  URLs and ``api.ddog-gov.com`` as it has previously done for other Datadog
  domains.

- Add telemetry for ECS queries.

- Agents are now built with Go 1.16.12.

- Add Kubelet queries telemetry.

- Add the ``kubernetes_node_annotations_as_host_aliases`` parameter to specify a list
  of Kubernetes node annotations that should be used as host aliases.
  If not set, it defaults to ``cluster.k8s.io/machine``.

- The experimental OTLP endpoint now supports the same settings as the OpenTelemetry Collector OTLP receiver v0.41.0.

- OTLP metrics tags are enriched when ``experimental.otlp.metrics.tag_cardinality`` is set to ``orchestrator``.
  This can also be controlled via the ``DD_OTLP_TAG_CARDINALITY`` environment variable.

- Make the Prometheus auto-discovery be able to schedule OpenMetrics V2 checks instead of legacy V1 ones.

  By default, the Prometheus annotations based auto-discovery will keep on scheduling openmetrics v1 check.
  But the agent now has a `prometheus_scrape.version` parameter that can be set to ``2`` to schedule the v2.

  The changes between the two versions of the check are described in
  https://datadoghq.dev/integrations-core/legacy/prometheus/#config-changes-between-versions

- Raised the max batch size of logs and events from `100` to `1000` elements. Improves
  performance in high volume scenarios.

- Add saturation metrics for network and memory.

- The Agent no longer logs spurious warnings regarding proxy-related environment variables
  ``DD_PROXY_NO_PROXY``, ``DD_PROXY_HTTP``, and ``DD_PROXY_HTTPS``.

- [corechecks/snmp] Add agent host as tag when ``use_device_id_as_hostname`` is enabled.

- [corechecks/snmp] Add profile metadata match syntax

- [corechecks/snmp] Support multiple symbols for profile metadata

- On Windows, the installer now uses a zipped Python integration folder, which
  should result in faster install times.

- Add support for Windows 2022 in published Docker images


.. _Release Notes_7.34.0_Bug Fixes:

Bug Fixes
---------

- APM: Fix SQL obfuscation error on statements using bind variables starting with digits

- Adds Windows NPM driver 1.3.1, which contains a fix for the system crash on system-probe shutdown under heavy load.

- ``DD_CLUSTER_NAME`` can be used to define the ``kube_cluster_name`` on EKS Fargate.

- On Windows the Agent now correctly detects Windows 11.

- Fixes an issue where the Docker check would undercount the number of
  stopped containers in the `docker.containers.stopped` and
  `docker.containers.stopped.total` metrics, accompanied by a "Cannot split
  the image name" error in the logs.

- Fixed a bug that caused a panic when running the docker check in cases
  where there are containers stuck in the "Removal in Progress" state.

- On EKS Fargate, the `container` check is scheduled while no suitable metrics collector is available, leading to excessive logging. Also fixes an issue with Liveness/Readiness probes failing regularly.

- Allow Prometheus scrape `tls_verify` to be set to `false` and
  change `label_to_hostname` type to `string`.

- Fixes truncated queries using temp tables in SQL Server.

- Fixes an NPM issue on Windows where if the first packet on a UDP flow
  is inbound, it is not counted correctly.

- On macOS, fix a bug where the Agent would not gracefully stop when sent a SIGTERM signal.

- Fix missing tags with eBPF checks (OOM Kill/TCP Queue Length) with some container runtimes (for instance, containerd 1.5).

- The experimental OTLP endpoint now ignores hostname attributes with localhost-like names for hostname resolution.

- Fixes an issue where cumulative-to-delta OTLP metrics conversion did not take the hostname into account.


.. _Release Notes_7.33.1:

7.33.1 / 6.33.1
======

.. _Release Notes_7.33.1_Prelude:

Prelude
-------

Release on: 2022-02-10


.. _Release Notes_7.33.1_Bug Fixes:

Bug Fixes
---------

- Fixes a panic that happens occasionally when handling tags for deleted
  containers or pods.

- Fixes security module failing to start on kernels 4.14 and 4.15.

.. _Release Notes_7.33.0:

7.33.0 / 6.33.0
======

.. _Release Notes_7.33.0_Prelude:

Prelude
-------

Release on: 2022-01-26

- Please refer to the `7.33.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7330>`_ for the list of changes on the Core Checks


.. _Release Notes_7.33.0_Upgrade Notes:

Upgrade Notes
-------------

- APM: The `apm_config.max_traces_per_second` setting no longer affects error sampling.
  To change the TPS for errors, use `apm_config.error_traces_per_second` instead.

- Starting from this version of the Agent, the Agent does not run on SLES 11.
  The new minimum requirement is SLES >= 12 or OpenSUSE >= 15 (including OpenSUSE 42).

- Changed the default value of `logs_config.docker_container_use_file` to `true`.
  The agent will now prefer to use files for collecting docker logs and fall back
  to the docker socket when files are not available.

- Upgrade Docker base image to ubuntu:21.10 as new stable release.


.. _Release Notes_7.33.0_New Features:

New Features
------------

- Autodiscovery of integrations now works with containerd.

- Metadata information sent by the Agent are now part of the flares. This will allow for easier troubleshooting of
  issues related to metadata.

- APM: Added credit card obfuscation. It is off by default and can be enabled using the
  env. var. DD_APM_OBFUSCATION_CREDIT_CARDS_ENABLED or `apm_config.obfuscation.credit_cards.enabled`.
  There is also an option to enable an additional Luhn checksum check in order to eliminate
  false negatives, but it comes with a performance cost and should not be used unless absolutely
  needed. The option is DD_APM_OBFUSCATION_CREDIT_CARDS_LUHN or `apm_config.obfuscation.credit_cards.luhn`.

- APM: The rare sampler can now be disabled using the environment variable DD_APM_DISABLE_RARE_SAMPLER
  or the `apm_config.disable_rare_sampler` configuration. By default the rare sampler catches 5 extra trace chunks
  per second on top of the head base sampling.
  The TPS is spread to catch all combinations of service, name, resource, http.status, error.type missed by
  head base sampling.

- APM: The error sampler TPS can be configured using the environment variable DD_APM_ERROR_TPS
  or the `apm_config.error_traces_per_second` configuration. It defaults to 10 extra trace chunks sampled
  per second on top of the base head sampling.
  The TPS is spread to catch all combinations of service, name, resource, http.status, and error.type.

- Add a generic `container` check. It generates `container.*` metrics based on all running containers, regardless of the container runtime used (among the supported ones).

- Added new option "container_labels_as_tags" that allows the Agent to
  extract container label values and set them as metric tags values. It's
  equivalent to the existing "docker_labels_as_tags", but it also works with
  containerd.

- CSPM: enable the usage of the print function in Rego rules.

- CSPM: add option to dump reports to file, when running checks manually.
  CSPM: constants can now be defined in rego rules and will be usable from rego rules.

- CWS: SECL expressions can now make use of predefined variables.
  `${process.pid}` variable refers to the pid of the process that
  trigger the event.

- Enable NPM DNS domain collection by default.

- Exposed additional *experimental* configuration for OTLP metrics
  translation via ``experimental.otlp.metrics``.

- Add two options under a new config prefix to send metrics
  to Vector instead of Datadog. `vector.metrics.enabled`
  must be set to true, along with `vector.metrics.url` that
  should be set to point to a Vector configured accordingly.

- The bpf syscall is now monitored by CWS; rules can be written on BPF commands.

- Add runtime settings support to the security-agent. Currenlty only the log-level
  is supported.

- APM: A new intake endpoint was added as /v0.6/traces, which accepts a new, more compact and efficient payload format.
  For more details, check: https://github.com/DataDog/datadog-agent/blob/7.33.0/pkg/trace/api/version.go#L78.


.. _Release Notes_7.33.0_Enhancement Notes:

Enhancement Notes
-----------------

- Adds Nomad namespace and datacenter to list of env vars extracted from Docker containers.

- Add a new `On-disk storage` section to `agent status` command.

- Run CSPM commands as a configurable user.
  Defaults to 'nobody'.

- CSPM: the findings query now defaults to `data.datadog.findings`

- The ``docker.exit`` service check has a new tag ``exit_code``.
  The ``143`` exit code is considered OK by default, in addition to ``0``.
  The Docker check supports a parameter ``ok_exit_codes`` to allow choosing exit codes that are considered OK.

- Allow dogstatsd replay files to be fully loaded into memory as opposed
  to relying on MMAP. We still default to MMAPing replay targets.

- ``kubernetes_state.node.*`` metrics are tagged with ``kubelet_version``,
  ``container_runtime_version``, ``kernel_version``, and ``os_image``.

- The Kube State Metrics Core check uses ksm v2.1.

- Lowercase the cluster names discovered from cloud providers
  to ease moving between different Datadog products.

- On Windows, allow enabling process discovery in the process agent by providing PROCESS_DISCOVERY_ENABLED=true to the msiexec command.

- Automatically extract the ``org.opencontainers.image.revision`` container label into the ``git.commit.sha`` tag.

- The experimental OTLP endpoint now can be configured through the ``experimental.otlp.receiver`` section and supports the same settings as the OpenTelemetry Collector OTLP receiver v0.38.0.

- The Process, APM, and Security agent now use the remote tagger introduced
  in Agent 7.26 by default. To disable it in the respective agent, the following
  settings need to be set to `false`:

  - apm_config.remote_tagger
  - process_config.remote_tagger
  - security_agent.remote_tagger

- Allows the remote tagger timeout at startup to be configured by setting the
  `remote_tagger_timeout_seconds` config value. It also now defaults to 30
  seconds instead of 5 minutes.

- Calls to cloud metadata APIs for metadata like hostnames and IP addresses
  are now cached and the existing values used when the metadata service
  returns an error.  This will prevent such metadata from temporarily
  "disappearing" from hosts.

- Datadog Process Agent Service is started automatically by the core agent on Windows when process discovery is enabled in the config.

- All packages - datadog-agent, datadog-iot-agent and datadog-dogstatsd -
  now support AlmaLinux and Rocky Linux distributions.

- If unrecognized ``DD_..`` environment variables are set, the agent will now log a warning at startup, to help catch deployment typos.

- Update the embedded ``pip`` version to 21.3.1 on Python 3 to
  allow the use of newer build backends.

- Metric series can now be submitted using the V2 API by setting
  `use_v2_api.series` to true.  This value defaults to false, and
  should only be set to true in internal testing scenarios.  The
  default will change in a future release.

- Add support for Windows 20H2 in published Docker images

- Add a new agent command to dump the content of the workloadmeta store ``agent workload-list``.
  The output of ``agent workload-list --verbose`` is included in the agent flare.


.. _Release Notes_7.33.0_Bug Fixes:

Bug Fixes
---------

- Strip special characters (\n, \r and \t) from OctetString

- APM: Fix bug where obfuscation fails for autovacuum sql text.
  For example, SQL text like `autovacuum: VACUUM ANALYZE fake.table` will no longer fail obfuscation.

- APM: Fix SQL obfuscation failures on queries with literals that include non alpha-numeric characters

- APM: Fix obfuscation error on SQL queries using the '!' operator.

- Fixed Windows Dockerfile scripts to make the ECS Fargate Python check run
  when the agent is deployed in ECS Fargate Windows.

- Fixing deadlock when stopping the agent righ when a metadata provider is scheduled.

- Fix a bug where container_include/exclude_metrics was applied on Autodiscovery when using Docker, preventing logs collection configured through container_include/exclude_logs.

- Fix inclusion of ``registry.json`` file in flare

- Fixes an issue where the agent would remove tags from pods or containers
  around 5 minutes after startup of either the agent itself, or the pods or
  containers themselves.

- APM: SQL query obfuscation doesn't drop redacted literals from the obfuscated query when they are preceded by a SQL comment.

- The Kube State Metrics Core check supports VerticalPodAutoscaler metrics.

- The experimental OTLP endpoint now uses the StartTimestamp field for reset detection on cumulative metrics transformations.

- Allow configuring process discovery check in the process agent when both regular process and container checks are off.

- Fix disk check reporting /dev/root instead of the actual
  block device path and missing its tags when tag_by_label
  is enabled.

- Remove occasionally hanging autodiscovery errors
  from the agent status once a pod is deleted.


.. _Release Notes_7.33.0_Other Notes:

Other Notes
-----------

- The Windows installer only creates the datadog.yaml file on new installs.


.. _Release Notes_7.32.4:

7.32.4 / 6.32.4
======

.. _Release Notes_7.32.4_Prelude:

Prelude
-------

Release on: 2021-12-22


- JMXFetch: Remove all dependencies on ``log4j`` and use ``java.util.logging`` instead.

.. _Release Notes_7.32.3:

7.32.3 / 6.32.3
======

.. _Release Notes_7.32.3_Prelude:

Prelude
-------

Release on: 2021-12-15

.. _Release Notes_7.32.3_Security Notes:

- Upgrade the log4j dependency to 2.12.2 in JMXFetch to fully address `CVE-2021-44228 <https://nvd.nist.gov/vuln/detail/CVE-2021-44228>`_ and `CVE-2021-45046 <https://nvd.nist.gov/vuln/detail/CVE-2021-45046>`_

.. _Release Notes_7.32.2:

7.32.2 / 6.32.2
======

.. _Release Notes_7.32.2_Prelude:

Prelude
-------

Release on: 2021-12-11


.. _Release Notes_7.32.2_Security Notes:

Security Notes
--------------

- Set ``-Dlog4j2.formatMsgNoLookups=True`` when starting the JMXfetch process to mitigate vulnerability described in `CVE-2021-44228 <https://nvd.nist.gov/vuln/detail/CVE-2021-44228>`_


.. _Release Notes_7.32.1:

7.32.1 / 6.32.1
======

.. _Release Notes_7.32.1_Prelude:

Prelude
-------

Release on: 2021-11-18


.. _Release Notes_7.32.1_Bug Fixes:

Bug Fixes
---------

- On ECS, fix the volume of calls to `ListTagsForResource` which led to ECS API throttling.

- Fix incorrect use of a namespaced PID with the host procfs when parsing mountinfo to ensure debugfs is mounted correctly.
  This issue was preventing system-probe startup in AWS ECS. This issue could also surface in other containerized environments
  where PID namespaces are in use and ``/host/proc`` is mounted.

- Fixes system-probe startup failure due to kernel version parsing on Linux 4.14.252+.
  This specifically was affecting versions of Amazon Linux 2, but could affect any Linux kernel in the 4.14 tree with sublevel >= 252.


.. _Release Notes_7.32.0:

7.32.0 / 6.32.0
======

.. _Release Notes_7.32.0_Prelude:

Prelude
-------

Release on: 2021-11-09

- Please refer to the `7.32.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7320>`_ for the list of changes on the Core Checks


.. _Release Notes_7.32.0_Upgrade Notes:

Upgrade Notes
-------------

- APM: Change default profiling intake to use v2 endpoint.

- CSPM the check subcommand is now part of the security-agent compliance.


.. _Release Notes_7.32.0_New Features:

New Features
------------

- On Kubernetes, add a `kube_priority_class` tag on metrics coming from pods with a priority class.

- Priority class name of pods are now collected and sent to the orchestration endpoint

- Autodiscovery can now resolve template variables and environment variables in log configurations.

- The Windows installer now offers US5 as a new site choice.

- APM: New telemetry was added to measure `/v.*/traces` endpoints latency and response size.
  These metrics are `datadog.trace_agent.receiver.{rate_response_bytes,serve_traces_ms}`.

- APM: Metrics are now available for Windows Pipes and UDS connections via datadog.trace_agent.receiver.{uds_connections,pipe_connections}.

- Introduce a new configuration parameter ``container_env_as_tags``
  to allow converting containerd containers' environment variables into tags.

- The "containerd" check is now supported on Windows.

- Add experimental support for writing agent-side CSPM compliance checks in Rego.

- Runtime security can now attach span/trace to event.

- Provides alternative implementation for process collection on Windows using performance counters.

- Add multi-line auto-sensing when tailing logs from file.
  It checks the 1000 first lines (or waits 30 seconds, whichever is first)
  when tailing for a list of known timestamp formats. If the
  number of matched lines is greater than the threshold it
  switches to the MultiLineHandler with the pattern matching
  the timestamp format. The pattern chosen is saved in the log
  config and is reused if the file rotates.  Use the new global config
  parameter ``logs_config.auto_multi_line_detection`` to enable
  the feature for the whole agent, or the per log integration config parameter ``auto_multi_line_detection``
  to enable the feature on a case by case basis.

- Added *experimental* support for OTLP metrics via
  experimental.otlp.{http_port,grpc_port} or their corresponding
  environment variables (DD_OTLP_{HTTP,GRPC}_PORT).

- Created a new process discovery check. This is a lightweight check that runs every 4 hours by default, and collects
  process metadata, so that Datadog can suggest potential integrations for the user to enable.

- Added new executable `readsecret_multiple_providers.sh` that allows the
  agent to read secrets both from files and Kubernetes secrets. Please refer
  to the `docs <https://docs.datadoghq.com/agent/guide/secrets-management>`_
  for more details.


.. _Release Notes_7.32.0_Enhancement Notes:

Enhancement Notes
-----------------

- KSM core check has a new `labels_as_tags` parameter to configure which pod labels should be used as datadog tag in an easier way than with the `label_joins` parameter.

- Add `namespace` to snmp listener config

- Remove `network_devices` from `datadog.yaml` configuration

- kubernetes state core check: add `kubernetes_state.job.completion.succeeded` and `kubernetes_state.job.completion.failed` metrics to report job completion as metrics in addition to the already existing service check.

- Add `use_device_id_as_hostname` in snmp check and snmp_listener configuration to use DeviceId as hostname for metrics and service checks

- APM: The maximum allowed tag value length has been increased to 25,000 bytes.

- Reduce memory usage when checks report new metrics every run. Most metrics are removed
  after two check runs without new samples. Rate, historate and monotonic count will be
  kept in memory for additional 25 hours after that. Number of check runs and the
  additional time can be changed with `check_sampler_bucket_commits_count_expiry` and
  `check_sampler_stateful_metric_expiration_time`. Metric expiration can be disabled
  entirely by setting `check_sampler_expire_metrics` to `false`.

- CSPM reports the agent version as part of the events

- Agents are now built with Go1.16.  This will have one user-visible change:
  on Linux, the process-level RSS metric for agent processes will be
  reduced from earlier versions.  This reflects a change in how memory
  usage is calculated, not a reduction in used memory, and is an artifact
  of the Go runtime `switching from MADV_FREE to MADV_DONTNEED
  <https://golang.org/doc/go1.16#runtime>`_.

- Tag Kubernetes containers with ``image_id`` tag.

- Eliminates the need to synchronize state between regular and RT process collection.

- APM: Added a configuration option to set the API key separately for Live
  Debugger. It can be set via `apm_config.debugger_api_key` or
  `DD_APM_DEBUGGER_API_KEY`.

- Update EP forwarder config to use intake v2 for ndm metadata

- Remove the `reason` tag from the `kubernetes_state.job.failed` metric to reduce cardinality

- the runtime security module of system-probe is now powered by DataDog/ebpf-manager instead of DataDog/ebpf.

- Security Agent: use exponential backoff for log warning when the security agent fails to
  connect to the system probe.

- APM: OTLP traces now supports semantic conventions from version 1.5.0 of the OpenTelemetry specification.

- Show enabled autodiscovery sources in the agent status

- Add namespace to SNMP integration and SNMP Listener to disambiguate
  devices with same IP.

- Add snmp corecheck autodiscovery

- Enable SNMP device metadata collection by default

- Reduced CPU usage when origin detection is used.

- The Windows installer now prioritizes user name from the command line over stored registry entries


.. _Release Notes_7.32.0_Bug Fixes:

Bug Fixes
---------

- Make sure ``DD_ENABLE_METADATA_COLLECTION="false"`` prevent all host metadata emission, including the initial one.

- Most checks are stripping tags with an empty value. KSM was missing this logic so that KSM specific metrics could have a tag with an empty value.
  They will now be stripped like for any other check.

- Fixed a regression that was preventing the Agent from retrying kubelet and docker connections in case of failure.

- Fix the cgroup collector to correctly pickup Cloud Foundry containers.

- Fix an issue where the orchestrator check would stop sending
  updates when run on as a cluster-check.

- Port python-tuf CVE fix on the embedded Python 2
  see `<https://github.com/theupdateframework/python-tuf/security/advisories/GHSA-wjw6-2cqr-j4qr>`_.

- Fix some string logging in the Windows installer.

- The flare command now correctly copies agent logs located in subdirectories
  of the agent's root log directory.

- Kubernetes state core check: `job.status.succeeded` and `job.status.failed` gauges were not sent when equal 0. 0 values are now sent.

- Tag Namespace and PV and PVC metrics correctly with ``phase`` instead of ``pod_phase``
  in the Kube State Metrics Core check.


.. _Release Notes_7.31.1:

7.31.1
======

.. _Release Notes_7.31.1_Prelude:

Prelude
-------

Release on: 2021-09-28

.. _Release Notes_7.31.1_Bug Fixes:

Bug Fixes
---------

- Fix CSPM not sending intake protocol causing lack of host tags.

.. _Release Notes_7.31.0:

7.31.0 / 6.31.0
======

.. _Release Notes_7.31.0_Prelude:

Prelude
-------

Release on: 2021-09-13

- Please refer to the `7.31.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7310>`_ for the list of changes on the Core Checks


.. _Release Notes_7.31.0_New Features:

New Features
------------

- Added `hostname_file` as a configuration option that can be used to set
  the Agent's hostname.

- APM: add a new HTTP proxy endpoint /appsec/proxy forwarding requests to Datadog's AppSec Intake API.

- Add a new parameter (auto_exit) to allow the Agent to exit automatically based on some condition. Currently, the only supported method "noprocess", triggers an exit if no other processes are visible to the Agent (taking into account HOST_PROC). Only available on POSIX systems.

- Allow specifying the destination for dogstatsd capture files, this
  should help drop captures on mounted volumes, etc. If no destination
  is specified the capture will default to the current behavior.

- Allow capturing/replaying dogstatsd traffic compressed with zstd.
  This feature is now enabled by default for captures, but can still
  be disabled.

- APM: Added endpoint for proxying Live Debugger requests.

- Adds the ability to change `log_level` in the process agent at runtime using ``process-agent config set log_level <log-level>``

- Runtime-security new command line allowing to trigger runtime security agent self test.


.. _Release Notes_7.31.0_Enhancement Notes:

Enhancement Notes
-----------------

- Introduce a `container_exclude_stopped_age` configuration option to allow
  the Agent to not autodiscover containers that have been stopped for a
  certain number of hours (by default 22). This makes restarts of the Agent
  not re-send logs for these containers.

- Add two new parameters to allow customizing APIServer connection parameters (CAPath, TLSVerify) without requiring to use a fully custom kubeconfig.

- Leverage Cloud Foundry application metadata to automatically tag Cloud Foundry containers. A label or annotation prefixed with ``tags.datadoghq.com/`` is automatically picked up and used to tag the application container when the cluster agent is configured to query the CC API.

- The ``agent configcheck`` command prints a message for checks that matched a
  container exclusion rule.

- Add calls to Cloudfoundry API for space and organization data to tag application containers with more up-to-date information compared to BBS API.

- The ``agent diagnose`` and ``agent flare`` commands no longer create error-level log messages when the diagnostics fail.
  These message are logged at the "info" level, instead.

- With the dogstatsd-replay feature allow specifying the number of
  iterations to loop over the capture file. Defaults to 1. A value
  of 0 loops forever.

- Collect net stats metrics (RX/TX) for ECS Fargate in Live Containers.

- EKS Fargate containers are tagged with ``eks_fargate_node``.

- The `agent flare` command will now include an error message in the
  resulting "local" flare if it cannot contact a running agent.

- The Kube State Metrics Core check sends a new metric ``kubernetes_state.pod.count``
  tagged with owner tags (e.g ``kube_deployment``, ``kube_replica_set``, ``kube_cronjob``, ``kube_job``).

- The Kube State Metrics Core check tags ``kubernetes_state.replicaset.count`` with a ``kube_deployment`` tag.

- The Kube State Metrics Core check tags ``kubernetes_state.job.count`` with a ``kube_cronjob`` tag.

- The Kube State Metrics Core check adds owner tags to pod metrics.
  (e.g ``kube_deployment``, ``kube_replica_set``, ``kube_cronjob``, ``kube_job``)

- Improve accuracy and reduce false positives on the collector-queue health
  check

- Support posix-compliant flags for process-agent. Shorthand flags for "p" (pid), "i" (info), and "v" (version) are
  now supported.

- The Agent now embeds Python-3.8.11, an upgrade from
  Python-3.8.10.

- APM: Updated the obfuscator to replace digits in IDs of SQL statement in addition to table names,
  when this option is enabled.

- The logs-agent now retries on an HTTP 429 response, where this had been treated as a hard failure.
  The v2 Event Intake will return 429 responses when it is overwhelmed.

- Runtime security now exposes change_time and modification_time in SECL.

- Add security-agent config file to flare

- Add ``min_collection_interval`` config to ``snmp_listener``

- TCP log collectors have historically closed sockets that are idle for more
  than 60 seconds.  This is no longer the case.  The agent relies on TCP
  keepalives to detect failed connections, and will otherwise wait indefinitely
  for logs to arrive on a TCP connection.

- Enhances the secrets feature to support arbitrarily named user
  accounts running the datadog-agent service. Previously the
  feature was hardcoded to `ddagentuser` or Administrator accounts
  only.


.. _Release Notes_7.31.0_Deprecation Notes:

Deprecation Notes
-----------------

- Deprecated non-posix compliant flags for process agent. A warning should now be displayed if one is detected.


.. _Release Notes_7.31.0_Bug Fixes:

Bug Fixes
---------

- Add `send_monotonic_with_gauge`, `ignore_metrics_by_labels`,
  and `ignore_tags` params to prometheus scrape. Allow values
  defaulting to `true` to be set to `false`, if configured.

- APM: Fix bug in SQL normalization that resulted in negative integer values to be normalized with an extra minus sign token.

- Fix an issue with autodiscovery on CloudFoundry where in case an application instance crash, a new integration configuration would not be created for the new app instance.

- Auto-discovered checks will not target init containers anymore in Kubernetes.

- Fixes a memory leak when the Agent is running in Docker environments. This
  leak resulted in memory usage growing linearly, corresponding with the
  amount of containers ever ran while the current Agent process was also
  running. Long-lived Agent processes on nodes with a lot of container churn
  would cause the Agent to eventually run out of memory.

- Fixes an issue where the `docker.containers.stopped` metric would have
  unpredictable tags. Now all stopped containers will always be reported with
  the correct tags.

- Fixes bug in enrich tags logic while a dogstatsd capture replay is in
  process; previously when a live traffic originID was not found in the
  captured state, no tags were enriched and the live traffic tagger was
  wrongfully skipped.

- Fixes a packaging issue on Linux where the unixodbc configuration files in
  /opt/datadog-agent/embedded/etc would be erased during Agent upgrades.

- Fix hostname detection when Agent is running on-host and monitoring containerized workload by not using hostname coming from containerized providers (Docker, Kubernetes)

- Fix default mapping for statefulset label in Kubernetes State Metric Core check.

- Fix handling of CPU metrics collected from cgroups when cgroup files are missing.

- Fix a bug where the status command of the security agent
  could crash if the agent is not fully initialized.

- Fixed a bug where the CPU check would not work within a container on Windows.

- Flare generation is no longer subject to the `server_timeout` configuration,
  as gathering all of the information for a flare can take quite some time.

- [corechecks/snmp] Support inline profile definition

- Fixes a bug where the Agent would hold on to tags from stopped ECS EC2 (but
  not Fargate) tags forever, resulting in increased memory consumption on EC2
  instances handling a lot of short scheduled tasks.

- On non-English Windows, the Agent correctly parses the output of `netsh`.


.. _Release Notes_7.31.0_Other Notes:

Other Notes
-----------

- The datadog-agent, datadog-iot-agent and datadog-dogstatsd deb packages now have a weak dependency (`Recommends:`) on the datadog-signing-keys package.


.. _Release Notes_7.30.2:

7.30.2
======

.. _Release Notes_7.30.2_Prelude:

Prelude
-------

Release on: 2021-08-23

This is a Windows-only release.

.. _Release Notes_7.30.2_Bug Fixes:

Bug Fixes
---------

- On Windows, disables ephemeral port range detection.  Fixes crash on non
  EN-US windows

.. _Release Notes_7.30.1:

7.30.1
======

.. _Release Notes_7.30.1_Prelude:

Prelude
-------

Release on: 2021-08-20

- Please refer to the `7.30.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7301>`_ for the list of changes on the Core Checks


.. _Release Notes_7.30.0:

7.30.0 / 6.30.0
======

.. _Release Notes_7.30.0_Prelude:

Prelude
-------

Release on: 2021-08-12

- Please refer to the `7.30.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7300>`_ for the list of changes on the Core Checks


.. _Release Notes_7.30.0_New Features:

New Features
------------

- APM: It is now possible to enable internal profiling of the trace-agent. Warning however that this will incur additional billing charges and should not be used unless agreed with support.

- APM: Added *experimental* support for Opentelemetry collecting via
  experimental.otlp.{http_port,grpc_port} or their corresponding
  environment variables (DD_OTLP_{HTTP,GRPC}_PORT).

- Kubernetes Autodiscovery now supports additional template variables:
  ``%%kube_pod_name%%``, ``%%kube_namespace%%`` and ``%%kube_pod_uid%%``.

- Add support for SELinux related events, like boolean value updates or enforcment status changes.


.. _Release Notes_7.30.0_Enhancement Notes:

Enhancement Notes
-----------------

- Reveals useful information within a SQL execution plan for Postgres.

- Add support to provide options to the obfuscator to change the behavior.

- APM: Added additional tags to profiles in AWS Fargate environments.

- APM: Main hostname acquisition now happens via gRPC to the Datadog Agent.

- Make the check_sampler bucket expiry configurable based on the number of `CheckSampler` commits.

- The cri check no longer sends metrics for stopped containers, in line with
  containerd and docker checks. These metrics were all zeros in the first
  place, so no impact is expected.

- Kubernetes State Core check: Job metrics corresponding to a Cron Job are tagged with a ``kube_cronjob`` tag.

- Environment autodiscovery is now used to selectively activate providers (kubernetes, docker, etc.) inside each component (tagger, host tags, hostname).

- When using a `secret_backend_command` STDERR is always logged with a debug log level. This eases troubleshooting a
  user's `secret_backend_command` in a containerized environment.

- `secret_backend_timeout` has been increased from 5s to 30s. This increases support for the slow to load
  Python script used for `secret_backend_command`. This was an issue when importing large libraries in a
  containerized environment.

- Increase default timeout to sync Kubernetes Informers from 2 to 5 seconds.

- The Kube State Metrics Core checks adds the global user-defined tags (``DD_TAGS``) by the default.

- If the new ``log_all_goroutines_when_unhealthy`` configuration parameter is set to true,
  when a component is unhealthy, log the stacktraces of the goroutines to ease the investigation.

- The amount of time the agent waits before scanning for new logs is now configurable with `logs_config.file_scan_period`

- Flares now include goroutine blocking and mutex profiles if enabled. New flare options
  were added to collect new profiles at the same time as cpu profile.

- Add a section about container inclusion/exclusion errors
  to the agent status command.

- Runtime Security now provide kernel related information
  as part of the flare.

- Python interpreter ``sys.executable`` is now set to the appropriate interpreter's
  executable path. This should allow ``multiprocessing`` to be able to spawn new
  processes since it will try to invoke the Python interpreter instead of the Agent
  itself. It should be noted though that the Pyton packages injected at runtime by
  the Agent are only available from the main process, not from any sub-processes.

- Add a single entrypoint script in the agent docker image.
  This script will be leveraged by a new version of the Helm chart.

- [corechecks/snmp] Add bulk_max_repetitions config

- Add device status snmp corecheck metadata

- [snmp/corecheck] Add interface.id_tags needed to correlated metadata interfaces with interface metrics

- In addition to the existing ``/readsecret.py`` script, the Agent container image
  contains another secret helper script ``/readsecret.sh``, faster and more reliable.

- Consider pinned CPUs (cpusets) when calculating CPU limit from cgroups.


.. _Release Notes_7.30.0_Bug Fixes:

Bug Fixes
---------

- APM: Fix SQL obfuscation on postgres queries using the tilde operator.

- APM: Fixed an issue with the Web UI on Internet Explorer.

- APM: The priority sampler service catalog is no longer unbounded. It is now limited to 5000 service & env combinations.

- Apply the `max_returned_metrics` parameter from prometheus annotations,
  if configured.

- Removes noisy error logs when collecting Cloud Foundry application containers

- For dogstatsd captures, Only serialize to disk the portion of buffers
  actually used by the payloads ingested, not the full buffer.

- Fix a bug in cgroup parser preventing from getting proper metrics in Container Live View when using CRI-O and systemd cgroup manager.

- Avoid sending duplicated ``datadog.agent.up`` service checks.

- When tailing logs from docker with `DD_LOGS_CONFIG_DOCKER_CONTAINER_USE_FILE=true` and a
  source container label is set the agent will now respect that label and use it as the source.
  This aligns the behavior with tailing from the docker socket.

- On Windows, when the host shuts down, handles the ``PreShutdown`` message to avoid the error ``The DataDog Agent service terminated unexpectedly.  It has done this 1 time(s).  The following corrective action will be taken in 60000 milliseconds: Restart the service.`` in Event Viewer.

- Fix label joins in the Kube State Metrics Core check.

- Append the cluster name, if found, to the hostname for
  ``kubernetes_state_core`` metrics.

- Ensure the health probes used as Kubernetes liveness probe are not failing in case of issues on the network or on an external component.

- Remove unplanned call between the process-agent and the the DCA when the
  orchestratorExplorer feature is disabled.

- [corechecks/snmp] Set default oid_batch_size to 5. High oid batch size can lead to timeouts.

- Agent collecting Docker containers on hosts with a lot of container churn
  now uses less memory by properly purging the respective tags after the
  containers exit. Other container runtimes were not affected by the issue.


.. _Release Notes_7.30.0_Other Notes:

Other Notes
-----------

- APM: The trace-agent no longer warns on the first outgoing request retry,
  only starting from the 4th.

- All Agent binaries are now compiled with Go ``1.15.13``

- JMXFetch upgraded to `0.44.2` https://github.com/DataDog/jmxfetch/releases/0.44.2

- Build environment changes:

  * omnibus-software: [cacerts] updating with latest: 2021-07-05 (#399)
  * omnibus-ruby: Support 'Recommends' dependencies for deb packages (#122)

- Runtime Security doesn't set the service tag with the
  `runtime-security-agent` value by default.


.. _Release Notes_7.29.1:

7.29.1
======

.. _Release Notes_7.29.1_Prelude:

Prelude
-------

Release on: 2021-07-13

This is a linux + docker-only release.


.. _Release Notes_7.29.1_New Features:

New Features
------------

- APM: Fargate stats and traces are now correctly computed, aggregated and present the expected tags.


.. _Release Notes_7.29.1_Bug Fixes:

Bug Fixes
---------

- APM: The value of the default env is now normalized during trace-agent initialization.


.. _Release Notes_7.29.0:

7.29.0 / 6.29.0
======

.. _Release Notes_7.29.0_Prelude:

Prelude
-------

Release on: 2021-06-24

- Please refer to the `7.29.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7290>`_ for the list of changes on the Core Checks


.. _Release Notes_7.29.0_Upgrade Notes:

Upgrade Notes
-------------

- Upgrade Docker base image to ubuntu:21.04 as new stable release.


.. _Release Notes_7.29.0_New Features:

New Features
------------

- New `extra_tags` setting and `DD_EXTRA_TAGS` environment variable can be
  used to specify additional host tags.

- Add network devices metadata collection

- APM: The obfuscator adds two new features (`dollar_quoted_func` and `keep_sql_alias`). They are off by default. For more details see PR 8071.
  We do not recommend using these features unless you have a good reason or have been recommended by support for your specific use-case.

- APM: Add obfuscator support for Postgres dollar-quoted string constants.

- Tagger state will now be stored for dogstatsd UDS traffic captures
  with origin detection. The feature will track the incoming traffic,
  building a map of traffic source processes and their source containers,
  then storing the relevant tagger state into the capture file. This will
  allow to not only replay the traffic, but also load a snapshot of the
  tagger state to properly tag replayed payloads in the dogstatsd pipeline.

- New `host_aliases` setting can be used to add custom host aliases in
  addition to aliases obtained from cloud providers automatically.

- Paths can now be relsolved using an eRPC request.

- Add time comparison support in SECL allow to write rules
  such as: `open.file.path == "/etc/secret" && process.created_at > 5s`


.. _Release Notes_7.29.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add the following new metrics to the ``kubernetes_state_core``.
  * ``node.ephemeral_storage_allocatable```
  * ``node.ephemeral_storage_capacity``

- Agent can now set hostname based on Azure instance metadata. See the new
  ``azure_hostname_style`` configuration option.

- Compliance agents can now generated multiple reports per run.

- Docker and Kubernetes log launchers will now be retried until
  one succeeds instead of falling back to the docker launcher by default.

- Increase payload size limit for `dbm-metrics` from `1 MB` to `20 MB`.

- Expose new `batch_max_size` and `batch_max_content_size` config settings for all logs endpoints.

- Adds improved cadence/resolution captures/replay to dogstatsd traffic
  captures. The new file format will store payloads with nanosecond
  resolution. The replay feature remains backward-compatible.

- Support fetching host tags using ECS task and EKS IAM roles.

- Improve the resiliency of the ``datadog-agent check`` command when running Autodiscovered checks.

- Adding the hostname to the host aliases when running on GCE

- Display more information when the error ``Could not initialize instance`` happens.
  JMXFetch upgraded to `0.44.0 <https://github.com/DataDog/jmxfetch/releases/0.44.0>`_

- Kubernetes pod with short-lived containers won't have a few logs of lines
  duplicated with both container tag (the stopped one and the running one) anymore
  while logs are being collected.
  Mount ``/var/log/containers`` and use ``logs_config.validate_pod_container_id``
  to enable this feature.

- The kube state metrics core check now tags pod metrics with a ``reason`` tag.
  It can be ``NodeLost``, ``Evicted`` or ``UnexpectedAdmissionError``.

- Implement the following synthetic metrics in the ``kubernetes_state_core``.
  * ``cronjob.count``
  * ``endpoint.count``
  * ``hpa.count``
  * ``vpa.count`

- Add system.cpu.interrupt on linux.

- Authenticate logs http input requests using the API key header rather than the URL path.

- Upgrade embedded Python 3 from 3.8.8 to 3.8.10. See
  `Python 3.8's changelog <https://docs.python.org/release/3.8.10/whatsnew/changelog.html>`_.

- Show autodiscovery errors from pod annotations in agent status.

- Paths are no longer limited to segments of 128 characters and a depth of 16. Each segment can now be up to 255 characters (kernel limit) and with a depth of up to 1740 parents.

- Add loader as ``snmp_listener.loader`` config

- Make SNMP Listener configs compatible with SNMP Integration configs

- The `agent stream-logs` command will use less CPU while idle.


.. _Release Notes_7.29.0_Security Notes:

Security Notes
--------------

- Redact the whole annotation "kubectl.kubernetes.io/last-applied-configuration" to ensure we don't expose secrets.


.. _Release Notes_7.29.0_Bug Fixes:

Bug Fixes
---------

- Imports the value of `non_local_traffic` to `dogstatsd_non_local_traffic`
  (in addition to `apm_config.non_local_traffic`) when upgrading from
  Datadog Agent v5.

- Fixes the Agent using 100% CPU on MacOS Big Sur.

- Declare `database_monitoring.{samples,metrics}` as known keys in order to remove "unknown key" warnings on startup.

- Fixes the container_name tag not being updated after Docker containers were
  renamed.

- Fixes CPU utilization being underreported on Windows hosts with more than one physical CPU.

- Fix CPU limit used for Live Containers page in ECS Fargate environments.

- Fix bug introduced in 7.26 where default checks were schedueld on ECS Fargate due to changes in entrypoint scripts.

- Fix a bug that can make the agent enable incompatible Autodiscovery listeners.

- An error log was printed when the creation date or the started date
  of a fargate container was not found in the fargate API payload.
  This would happen even though it was expected to not have these dates
  because of the container being in a given state.
  This is now fixed and the error is only printed when it should be.

- Fix the default value of the configuration option ``forwarder_storage_path`` when ``run_path`` is set.
  The default value is ``RUN_PATH/transactions_to_retry`` where RUN_PATH is defined by the configuration option ``run_path``.

- In some cases, compliance checks using YAML file with JQ expressions were failing due to discrepencies between YAML parsing and gojq handling.

- On Windows, fixes inefficient string conversion

- Reduce CPU usage when logs agent is unable to reach an http endpoint.

- Fixed no_proxy depreciation warning from being logged too frequently.
  Added better warnings for when the proxy behavior could change.

- Ignore CollectorStatus response from orchestrator-intake in the process-agent to prevent changing realtime mode interval to default 2s.

- Fixes an issue where the Agent would not retry resource tags collection for
  containers on ECS if it could retrieve only a subset of tags. Now it will
  keep on retrying until the complete set of tags is collected.

- Fix noisy configuration error when specifying a proxy config and using secrets management.

- Reduce amount of log messages on windows when tailing log files.


.. _Release Notes_7.29.0_Other Notes:

Other Notes
-----------

- JMXFetch upgraded to `0.44.1 <https://github.com/DataDog/jmxfetch/releases/0.44.1>`_


.. _Release Notes_7.28.1:

7.28.1
======

.. _Release Notes_7.28.1_Prelude:

Prelude
-------

Release on: 2021-05-31

- Please refer to the `7.28.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7281>`_ for the list of changes on the Core Checks


.. _Release Notes_7.28.0:

7.28.0 / 6.28.0
======

.. _Release Notes_7.28.0_Prelude:

Prelude
-------

Release on: 2021-05-26

- Please refer to the `7.28.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7280>`_ for the list of changes on the Core Checks


.. _Release Notes_7.28.0_Upgrade Notes:

Upgrade Notes
-------------

- Change base Docker image used to build the Agent images, moving from ``debian:bullseye`` to ``ubuntu:20.10``.
  In the future the Agent will follow Ubuntu stable versions.

- Windows Docker images based on Windows Core are now provided. Checks that didn't work on Nano should work on Core.


.. _Release Notes_7.28.0_New Features:

New Features
------------

- APM: Add a new feature flag ``component2name`` which determines the ``component`` tag value
  on a span to become its operation name. This facititates compatibility with Opentracing.

- Adds a functionality to allow capturing and replaying
  of UDS dogstatsd traffic.

- Expose new ``aggregator.submit_event_platform_event`` python API with two supported event types:
  ``dbm-samples`` and ``dbm-metrics``.

- Runtime security reports environment variables.

- Runtime security now reports command line arguments as part of the
  exec events.

- The ``args_flags`` and ``args_options`` were added to the SECL
  language to ease the writing of runtime security rules based
  on command line arguments.
  ``args_flags`` is used to catch arguments that start by either one
  or two hyphen characters but do not accept any associated value.

  Examples:

  - ``version`` is part of ``args_flags`` for the command ``cat --version``
  - ``l`` and ``n`` both are in ``args_flags`` for the command ``netstat -ln``
  - ``T=8`` and ``width=8`` both are in ``args_options`` for the command
    ``ls -T 8 --width=8``.

- Add support for ARM64 to the runtime security agent


.. _Release Notes_7.28.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add ``oid_batch_size`` configuration as init and instance config

- Add ``oid_batch_size`` config to snmp_listener

- Group the output of ``agent tagger-list`` by entity and by source.

- On Windows on a Domain Controller, if no domain name is specified, the installer will use the controller's joined domain.

- Windows installer can now use the command line key ``EC2_USE_WINDOWS_PREFIX_DETECTION`` to set the config
  value of ``ec2_use_windows_prefix_detection``

- APM: The trace writer will now consider 408 errors to be retriable.

- Build RPMs that can be installed in FIPS mode. This change doesn't affect SUSE RPMs.

  RPMs are now built with RPM 4.15.1 and have SHA256 digest headers, which are required by RPM on CentOS 8/RHEL 8 when running in FIPS mode.

  Note that newly built RPMs are no longer installable on CentOS 5/RHEL 5.

- Make the check_sampler bucket expiry configurable

- The Agent can be configured to replace colon ``:`` characters in the ECS resource tag keys by underscores ``_``.
  This can be done by enabling ``ecs_resource_tags_replace_colon: true`` in the Agent config file
  or by configuring the environment variable ``DD_ECS_RESOURCE_TAGS_REPLACE_COLON=true``.

- Add ``jvm.gc.old_gen_size`` as an alias for ``Tenured Gen``.
  Prevent double signing of release artifacts.

- JMXFetch upgraded to `v0.44.0 <https://github.com/DataDog/jmxfetch/releases/0.44.0>`_.

- The ``kubernetes_state_core`` check now collects two new metrics ``kubernetes_state.pod.age`` and ``kubernetes_state.pod.uptime``.

- Improve ``logs/sender`` throughput by adding optional concurrency for serializing & sending payloads.

- Make kube_replica_set tag low cardinality

- Runtime Security now supports regexp in SECL rules.

- Add loader tag to snmp telemetry metrics

- Network Performance Monitoring for windows now collects DNS stats, connections will be shows in the networks -> DNS page.


.. _Release Notes_7.28.0_Deprecation Notes:

Deprecation Notes
-----------------

- For internal profiling of agent processes, the ``profiling`` option
  has been renamed to ``internal_profiling`` to avoid confusion.

- The single dash variants of the system-probe flags are now deprecated. Please use ``--config`` and ``--pid`` instead.


.. _Release Notes_7.28.0_Bug Fixes:

Bug Fixes
---------

- APM: Fixes bug where long service names and operation names were not normalized correctly.

- On Windows, fixes a bug in process agent in which the process agent
  would become unresponsive.

- The Windows installer compares the DNS domain name and the joined domain name using a case-insensitive compare.
  This avoids an incorrect warning when the domain names match but otherwise have different cases.

- Replace usage of ``runtime.NumCPU`` when used to compute metrics related to CPU Hosts. On some Unix systems,
  ``runtime.NumCPU`` can be influenced by CPU affinity set on the Agent, which should not affect the metrics
  computed for other processes/containers. Affects the CPU Limits metrics (docker/containerd) as well as the
  live containers page metrics.

- Fix issue where Kube Apiserver cache sync timeout configuration is not used.

- Fix the usage of ``DD_ORCHESTRATOR_EXPLORER_ORCHESTRATOR_DD_URL`` and ``DD_ORCHESTRATOR_EXPLORER_MAX_PER_MESSAGE`` environment variables.

- Fix a ``panic`` that could occur in Docker AD listener when doing ``docker inspect`` fails

- Fix a small leak where the Agent in some cases keeps in memory identifiers corresponding to dead objects (pods, containers).

- Log file byte count now works correctly on Windows.

- Agent log folder on Mac is moved from ``/var/log/datadog`` to ``/opt/datadog-agent/logs``. A link will be created at
  ``/var/log/datadog`` pointing to ``/opt/datadog-agent/logs`` to maintain the compatibility. This is to workaround the
  issue that some Mac OS releases purge ``/var/log`` folder on ugprade.

- Packaging: ensure only one pip3 version is shipped in ``embedded/`` directory

- Fix eBPF runtime compilation errors with ``tcp_queue_length`` and ``oom_kill`` checks on Ubuntu 20.10.

- Add a validation step before accepting metrics set in HPAs.
  This ensures that no obviously-broken metric is accepted and goes on to
  break the whole metrics gathering process.

- The Windows installer now log only once when it fails to replace a property.

- Windows installer will not abort if the Server service is not running (introduced in 6.24.0/7.24.0).


.. _Release Notes_7.28.0_Other Notes:

Other Notes
-----------

- The Agent, Logs Agent and the system-probe are now compiled with Go ``1.15.11``

- Bump embedded Python 3 to ``3.8.8``


.. _Release Notes_7.27.1:

7.27.1 / 6.27.1
======

.. _Release Notes_7.27.1_Prelude:

Prelude
-------

Release on: 2021-05-07

This is a Windows-only release (MSI and Chocolatey installers only).

.. _Release Notes_7.27.1_Bug Fixes:

Bug Fixes
---------

- On Windows, exit system-probe if process-agent has not queried for connection data for 20 consecutive minutes.
  This ensures excessive system resources are not used while connection data is not being sent to Datadog.


.. _Release Notes_7.27.0:

7.27.0 / 6.27.0
======

.. _Release Notes_7.27.0_Prelude:

Prelude
-------

Release on: 2021-04-14

- Please refer to the `7.27.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7270>`_ for the list of changes on the Core Checks


.. _Release Notes_7.27.0_Upgrade Notes:

Upgrade Notes
-------------

- SECL and JSON format were updated to introduce the new attributes. Legacy support was added to avoid breaking
  existing rules.

- The `overlay_numlower` integer attribute that was reported for files
  and executables was unreliable. It was replaced by a simple boolean
  attribute named `in_upper_layer` that is set to true when a file
  is either only on the upper layer of an overlayfs filesystem, or
  is an altered version of a file present in a base layer.


.. _Release Notes_7.27.0_New Features:

New Features
------------

- APM: Add support for AIX/ppc64. Only POWER8 and above is supported.

- Adds support for Kubernetes namespace labels as tags extraction (kubernetes_namespace_labels_as_tags).

- Add snmp corecheck implementation in go

- APM: Tracing clients no longer need to be sending traces marked
  with sampling priority 0 (AUTO_DROP) in order for stats to be correct.

- APM: A new discovery endpoint has been added at the /info path. It reveals
  information about a running agent, such as available endpoints, version and
  configuration.

- APM: Add support for filtering tags by means of apm_config.filter_tags or environment
  variables DD_APM_FILTER_TAGS_REQUIRE and DD_APM_FILTER_TAGS_REJECT.

- Dogstatsd clients can now choose the cardinality of tags added by origin detection per metrics
  via the tag 'dd.internal.card' ("low", "orch", "high").

- Added two new metrics to the Disk check: read_time and write_time.

- The Agent can store traffic on disk when the in-memory retry queue of the
  forwarder limit is reached. Enable this capability by setting
  `forwarder_storage_max_size_in_bytes` to a positive value indicating
  the maximum amount of storage space, in bytes, that the Agent can use
  to store traffic on disk.

- PCF Containers custom tags can be extracted from environment
  variables based on an include and exclude lists mechanism.

- NPM is now supported on Windows, for Windows versions 2016 and above.

- Runtime security now report command line arguments as part of the
  exec events.

- Process credentials are now tracked by the runtime security agent. Various user and group attributes are now
  collected, along with kernel capabilities.

- File metadata attributes are now available for all events. Those new attributes include uid, user, gid, group, mode,
  modification time and change time.

- Add config parameters to enable fim and runtime rules.

- Network Performance Monitoring for Windows instruments DNS.  Network data from Windows hosts will be tagged with the domain tag, and the DNS page will show data for Windows hosts.


.. _Release Notes_7.27.0_Enhancement Notes:

Enhancement Notes
-----------------

- Improves sensitive data scrubbing in URLs

- Includes UTC time (unless already in UTC+0) and millisecond timestamp in status logs. Flare archive filename now timestamped in UTC.

- Automatically set debug log_level when the '--flare' option is used with the  JMX command

- Number of matched lines is displayed on the status page for each source using multi_line log processing rules.

- Add public IPv4 for EC2/GCE instances to host network metadata.

- Add ``loader`` config to snmp_listener

- Add snmp corecheck extract value using regex

- Remove agent MaxNumWorkers hard limit that cap the number of check runners
  to 25. The removal is motivated by the need for some users to run thousands
  of integrations like snmp corecheck.

- APM: Change in the stats payload format leading to reduced CPU and memory usage.
  Use of DDSketch instead of GKSketch to aggregate distributions leading to more accurate high percentiles.

- APM: Removal of sublayer metric computation improves performance of the trace agent (CPU and memory).

- APM: All API endpoints now respond with the "Datadog-Agent-Version" HTTP response header.

- Query application list from Cloud Foundry Cloud Controller API to get up-to-date application names for tagging containers and metrics.

- Introduce a clc_runner_id config option to allow overriding the default
  Cluster Checks Runner identifier. Defaults to the node name to make it
  backwards compatible. It is intended to allow binpacking more than a single
  runner per node.

- Improve migration path when shifting docker container tailing
  from the socket to file. If tailing from file for Docker
  containers is enabled, container with an existing entry
  relative to a socket tailer will continue being tailed
  from the Docker socket unless the following newly introduced
  option is set to true:  ``logs_config.docker_container_force_use_file``
  It aims to allow smooth transition to file tailing for Docker
  containers.

- (Unix only) Add `go_core_dump` flag to generate core dumps on Agent crashes

- JSON payload serialization and compression now uses shared input and output buffers to reduce
  total allocations in the lifetime of the agent.

- On Windows the comments in the datadog.yaml file are preserved after installation.

- Add kube_region and kube_zone tags to node metrics reported by the kube-state-metrics core check

- Implement the following synthetic metrics in the ``kubernetes_state_core`` check to mimic the legacy ``kubernetes_state`` one.
  * ``persistentvolumes.by_phase``
  * ``service.count``
  * ``namespace.count``
  * ``replicaset.count``
  * ``job.count``
  * ``deployment.count``
  * ``daemonset.count``
  * ``statefulset.coumt``

- Minor improvements to agent log-stream command. Fixed timestamp, added host name,
  use redacted log message instead of raw message.

- NPM - Improve accuracy of retransmits tracking on kernels >=4.7

- Orchestrator explorer collection is no longer handled by the cluster-agent directly but
  by a dedicated check.

- prometheus_scrape.checks may now be defined as an environmnet variable DD_PROMETHEUS_SCRAPE_CHECKS formatted as JSON

- Runtime security module doesn't stop on first policies file
  load error and now send an event with a report of the load.

- Sketch series payloads are now compressed as a stream to reduce
  buffer allocations.

- The Datadog Agent won't try to connect to kubelet anymore if it's not running in a Kubernetes cluster.


.. _Release Notes_7.27.0_Known Issues:

Known Issues
------------

- On Linux kernel versions < 3.15, conntrack (used for NAT info for connections)
  sampling is not supported, and conntrack updates will be aborted if a higher
  rate of conntrack updates from the system than set by
  system_probe_config.conntrack_rate_limit is detected. This is done to limit
  excessive resource consumption by the netlink conntrack update system. To
  keep using this system even with a high rate of conntrack updates, increase
  the system_probe_config.conntrack_rate_limit. This can potentially lead to
  higher cpu usage.


.. _Release Notes_7.27.0_Deprecation Notes:

Deprecation Notes
-----------------

- APM: Sublayer metrics (trace.<SPAN_NAME>.duration and derivatives) computation
  is removed from the agent in favor of new sublayer metrics generated in the backend.


.. _Release Notes_7.27.0_Bug Fixes:

Bug Fixes
---------

- Fixes bug introduced in #7229

- Adds a limit to the number of DNS stats objects the DNSStatkeeper can have at any given time. This can alleviate memory issues on hosts doing high numbers of DNS requests where network performance monitoring is enabled.

- Add tags to ``snmp_listener`` network configs. This is needed since user
  switching from Python SNMP Autodiscovery will expect to have tags to be
  available with Agent SNMP Autodiscovery (snmp_listener) too.

- APM: When UDP is not available for Dogstatsd, the trace-agent can now use any other
  available alternative, such as UDS or Windows Pipes.

- APM: Fixes a bug where nested SQL queries may occasionally result in bad obfuscator output.

- APM: All Datadog API key usage is sanitized to exclude newlines and other control characters.

- Exceeding the conntrack rate limit (system_probe_config.conntrack_rate_limit)
  would result in conntrack updates from the system not being processed
  anymore

- Address issue with referencing the wrong repo tag for Docker image by
  simplifying logic in DockerUtil.ResolveImageNameFromContainer to prefer
  Config.Image when possible.

- Fix kernel version parsing when subversion/patch is > 255, so eBPF program loading does not fail.

- Agent host tags are now correctly removed from the in-app host when the configured ``tags``/``DD_TAGS`` list is empty or not defined.

- Fixes scheduling of non-working container checks introduced by environment autodiscovery in 7.26. Features can now be exluded from autodiscovery results through `autoconfig_exclude_features`.
  Example: autoconfig_exclude_features: ["docker","cri"] or DD_AUTOCONFIG_EXCLUDE_FEATURES="docker cri"
  Fix typo in variable used to disable environment autodiscovery and make it usable in `datadog.yaml`. You should now set `autoconfig_from_environment: false` or `DD_AUTOCONFIG_FROM_ENVIRONMENT=false`

- Fixes limitation of runtime autodiscovery which would not allow to run containerd check without cri check enabled. Fixes error logs in non-Kubernetes environments.

- Fix missing tags on Dogstatsd metrics when DD_DOGSTATSD_TAG_CARDINALITY=orchestrator (for instance, task_arn on Fargate)

- Fix a panic in the `system-probe` part of the `tcp_queue_length` check when running on nodes with several CPUs.

- Fix agent crashes from Python interpreter being freed too early. This was
  most likely to occur as an edge case during a shutdown of the agent where
  the interpreter was destroyed before the finalizers for a check were
  invoked by finalizers.

- Do not make the liveness probe fail in case of network connectivity issue.
  However, if the agent looses network connectivity, the readiness probe may still fail.

- On Windows, using process agent, fixes the virtual CPU count when the
  device has more than one physical CPU (package)).

- On Windows, fixes problem in process agent wherein windows processes
  could not completely exit.

- (macOS only) Apple M1 chip architecture information is now correctly reported.

- Make ebpf compiler buildable on non-GLIBC environment.

- Fix a bug preventing pod updates to be sent due to the Kubelet exposing
  unreliable resource versions.

- Silence INFO and WARNING gRPC logs by default. They can be re-enabled by
  setting GRPC_GO_LOG_VERBOSITY_LEVEL to either INFO or WARNING.


.. _Release Notes_7.27.0_Other Notes:

Other Notes
-----------

- Network monitor now fails to load if conntrack initialization fails on
  system-probe startup. Set network_config.ignore_conntrack_init_failure
  to true to reverse this behavior.

- When generating the permissions.log file for a flare, if the owner of a file
  no longer exists in the system, return its id instead instead of failing.

- Upgrade embedded openssl to ``1.1.1k``.


.. _Release Notes_7.26.0:

7.26.0 / 6.26.0
======

.. _Release Notes_7.26.0_Prelude:

Prelude
-------

Release on: 2021-03-02

- Please refer to the `7.26.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7260>`_ for the list of changes on the Core Checks


.. _Release Notes_7.26.0_Upgrade Notes:

Upgrade Notes
-------------

- ``forwarder_retry_queue_payloads_max_size`` takes precedence over the deprecated
  ``forwarder_retry_queue_max_size``. If ``forwarder_retry_queue_max_size``
  is not set, you are not affected by this change. If
  ``forwarder_retry_queue_max_size`` is set, but
  ``forwarder_retry_queue_payloads_max_size`` is not set, the Agent uses
  ``forwarder_retry_queue_max_size * 2MB``
  as the value of ``forwarder_retry_queue_payloads_max_size``. It is
  recommended to configure ``forwarder_retry_queue_payloads_max_size`` and
  remove ``forwarder_retry_queue_max_size`` from the Agent configuration.

- Docker image: remove Docker volumes for ``/etc/datadog-agent`` and ``/tmp``
  as it prevents to inherit from Datadog Agent image. It was originally done
  to allow read-only rootfs on Kubernetes, so in order to continue supporting
  this feature, relevant volumes are created in newer Kubernetes manifest or
  Helm chart >= 2.6.9

.. _Release Notes_7.26.0_New Features:

New Features
------------

- APM: Support SQL obfuscator feature to replace consecutive digits in table names.

- APM: Add an endpoint to receive apm stats from tracers.

- Agent discovers by itself which container AD features and checks should be
  scheduled without having to specify any configuration. This works for
  Docker, Containerd, ECS/EKS Fargate and Kubernetes.
  It also allows to support heterogeneous nodes with a single configuration
  (for instance a Kubernetes DaemonSet could cover nodes running Containerd
  and/or Docker - activating relevant configuration depending on node
  configuration).
  This feature is activated by default and can be de-activated by setting
  environment variable ``AUTCONFIG_FROM_ENVIRONMENT=false``.

- Adds a new agent command ``stream-logs`` to stream the logs being processed by the agent.
  This will help diagnose issues with log integrations.

- Submit host tags with log events for a configurable time duration
  to avoid potential race conditions where some tags might not be
  available to all backend services on freshly provisioned instances.

- Added no_proxy_nonexact_match as a configuration setting which
  allows non-exact URL and IP address matching. The new behavior uses
  the go http proxy function documented here
  https://godoc.org/golang.org/x/net/http/httpproxy#Config
  If the new behavior is disabled, a warning will be logged if a url or IP
  proxy behavior will change in the future.

- The Quality of Service of pods is now collected and sent to the orchestration endpoint.

- Runtime-security new command line allowing to trigger a process cache dump..

- Support Prometheus Autodiscovery for Kubernetes Pods.

- The core agent now exposes a gRPC API to expose tags to the other agents.
  The following settings are now introduced to allow each of the agents to use
  this API (they all default to false):

  - apm_config.remote_tagger
  - logs_config.remote_tagger
  - process_config.remote_tagger

- New perf map usage metrics.

- Add unofficial arm64 support to network tracer in system-probe.

- system-probe: Add optional runtime compilation of eBPF programs.


.. _Release Notes_7.26.0_Enhancement Notes:

Enhancement Notes
-----------------

- APM: Sublayer metrics (trace.<SPAN_NAME>.duration and derivatives) computation
  in agent can be disabled with feature flags disable_sublayer_spans, disable_sublayer_stats.
  Reach out to support with questions about this metric.

- APM: Automatically activate non-local trafic (i.e. listening on 0.0.0.0) for APM in containerized environment if no explicit setting is set (bind_host or apm_non_local_traffic)

- APM: Add a tag allowing trace metrics from synthetic data to
  be aggregated independently.

- Consider the task level resource limits if the container level resource limits aren't defined on ECS Fargate.

- Use the default agent transport for host metadata calls.
  This allows usage of the config ``no_proxy`` setting for host metadata calls.
  By default cloud provider IPs are added to the transport's ``no_proxy`` list.
  Added config flag ``use_proxy_for_cloud_metadata`` to disable this behavior.

- GOMAXPROCS is now set automatically to match the allocated CPU cgroup quota.
  GOMAXPROCS can now also be manually specified and overridden in millicore units.
  If no quota or GOMAXPROCS value is set it will default to the original behavior.

- Added ``--flare`` flag to ``jmx (list|collect)`` commands to save check results to the agent logs directory.
  This enables flare to pick up jmx command results.

- Kubernetes events are now tagged with kube_service, kube_daemon_set, kube_job and kube_cronjob.
  Note: Other object kinds are already supported (pod_name, kube_deployment, kube_replica_set).

- Expose logs agent pipeline latency in the status page.

- Individual DEB packages are now signed.

- Docker container, when not running in a Kubernetes
  environment may now be tailed from their log file.
  The Agent must have read access to /var/lib/docker/containers
  and Docker containers must use the JSON logging driver.
  This new option can be activated using the new configuration
  flag ``logs_config.docker_container_use_file``.

- File tailing from a kubernetes pod annotation is
  now supported. Note that the file path is relative
  to the Agent and not the pod/container bearing
  the annotation.


.. _Release Notes_7.26.0_Bug Fixes:

Bug Fixes
---------

- APM: Group arrays of consecutive '?' identifiers

- Fix agent panic when UDP port is busy and dogstatsd_so_rcvbuf is configured.

- Fix a bug that prevents from reading the correct container resource limits on ECS Fargate.

- Fix parsing of dogstatsd event strings that contained negative lengths for
  event title and/or event text length.

- Fix sending duplicated kubernetes events.

- Do not invoke the secret backend command (if configured) when the agent
  health command/agent container liveness probe is called.

- Fix parsing of CLI options of the ``agent health`` command


.. _Release Notes_7.26.0_Other Notes:

Other Notes
-----------

- Bump gstatus version from 1.0.4 to 1.0.5.

- JMXFetch upgraded from `0.41.0 <https://github.com/DataDog/jmxfetch/releases/0.41.0>`_
  to `0.42.0 <https://github.com/DataDog/jmxfetch/releases/0.42.0>`_


.. _Release Notes_7.25.1:

7.25.1
======

.. _Release Notes_7.25.1_Prelude:

Prelude
-------

Release on: 2021-01-26


.. _Release Notes_7.25.1_Bug Fixes:

Bug Fixes
---------

- Fix "fatal error: concurrent map read and map write" due to reads of
  a concurrently mutated map in inventories.payload.MarshalJSON()

- Fix an issue on arm64 where non-gauge metrics from Python checks
  were treated as gauges.

- On Windows, fixes uninstall/upgrade problem if core agent is not running
  but other services are.

- Fix NPM UDP destination address decoding when source address ends with `.8` during offset guessing.

- On Windows, changes the password generating algorithm to have a minimum
  length of 16 and a maximum length of 20 (from 12-18).  Improves compatibility
  with environments that have longer password requirements.

=============
Release Notes
=============

.. _Release Notes_7.25.0:

7.25.0 / 6.25.0
======

.. _Release Notes_7.25.0_Prelude:

Prelude
-------

Release on: 2021-01-14

- Please refer to the `7.25.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7250>`_ for the list of changes on the Core Checks


.. _Release Notes_7.25.0_New Features:

New Features
------------

- Add `com.datadoghq.ad.tags` container auto-discovery label in AWS Fargate environment.

- Package the gstatus command line tool binary for GlusterFS integration metric collection.

- Queried domain can be tracked as part of DNS stats

- APM: The agent is now able to skip top-level span computation in cases when
  the client has marked them by means of the Datadog-Client-Computed-Top-Level
  header.

- APM: The maximum allowed key length for tags has been increased from 100 to 200.

- APM: Improve Oracle SQL obfuscation support.

- APM: Added support for Windows pipes. To enable it, set the pipe path using
  DD_APM_WINDOWS_PIPE_NAME. For more details check `PR #6615 <https://github.com/DataDog/datadog-agent/pull/6615>`_

- Pause containers are now detected and auto excluded based on the `io.kubernetes` container labels.

- APM: new `datadog_agent.obfuscate_sql_exec_plan` function exposed to python
  checks to enable obfuscation of json-encoded SQL Query Execution Plans.

- APM: new `obfuscate_sql_values` option in `apm_config.obfuscation` enabling optional obfuscation
  of SQL queries contained in JSON data collected from some APM services (ES & Mongo)


.. _Release Notes_7.25.0_Enhancement Notes:

Enhancement Notes
-----------------

- Support the ddog-gov.com site option in the Windows
  GUI installer.

- Adds config setting for ECS metadata endpoint client timeout (ecs_metadata_timeout), value in milliseconds.

- Add `loader` config to allow selecting specific loader
  at runtime. This config is available at `init_config`
  and `instances` level.

- Added additional container information to the status page when collect all container logs is enabled in agent status.

- On Windows, it will no longer be required to supply the ddagentuser name
  on upgrade.  Previously, if a non-default or domain user was used, the
  same user had to be provided on subsequent upgrades.

- Added `--flare` flag to `agent check` to save check results to the agent logs directory.
  This enables flare to pick up check results.

- Added new config option for JMXFetch collect_default_jvm_metrics that enables/disables
  default JVM metric collection.

- Allow empty message for DogStatsD events (e.g. "_e{10,0}:test title|")

- Expires the cache key for availability of ECS metadata endpoint used to fetch
  EC2 resource tags every 5 minutes.

- Data coming from kubernetes pods now have new kube_ownerref_kind and
  kube_ownerref_name tags for each of the pod's OwnerRef property, indicating
  its Kind and Name, respectively.

- We improved the way Agents get the Kubernetes cluster ID from the Cluster Agent.
  It used to be that the cluster agent would create a configmap which had to be
  mounted as an env variable in the agent daemonset, blocking the process-agent
  from starting if not found. Now the process-agent will start, only the Kubernetes
  Resources collection will be blocked.

- Events sent by the runtime security agent to the backend use
  a new taxonomy.

- Scrub container args as well for orchestrator explorer.

- Support custom autodiscovery identifiers on Kubernetes using the `ad.datadoghq.com/<container_name>.check.id` pod annotation.

- The CPU check now collects system-wide context switches on Linux.

- Add ``--table`` option to ``agent check`` command to output
  results in condensed tabular format instead of JSON.

- APM: improve performance by changing the msgpack serialization implementation.

- APM: improve the performance of the msgpack deserialization for the v0.5 payload format.

- APM: improve performance of trace processing by removing some heap allocations.

- APM: improve sublayer computation performance by reducing the number of heap allocations.

- APM: improved stats computation performance by removing some string concatenations.

- APM: improved trace signature computation by avoiding heap allocations.

- APM: improve stats computation performance.

- Update from alpine:3.10 to alpine:3.12 the base image in Dogstatsd's Dockerfiles.


.. _Release Notes_7.25.0_Deprecation Notes:

Deprecation Notes
-----------------

- APM: remove the already deprecated apm_config.extra_aggregators config option.


.. _Release Notes_7.25.0_Bug Fixes:

Bug Fixes
---------

- Fix macos `dlopen` failures by ensuring cmake preserves the required runtime search path.

- Fix memory leak on check unscheduling, which could be noticeable for checks
  submitting large amounts of metrics/tags.

- Exclude pause containers using the `cdk/pause.*` image.

- Fixed missing some Agent environment variables in the flare

- Fix a bug that prevented the logs Agent from discovering the correct init containers `source` and `service` on Kubernetes.

- The logs agent now uses the container image name as logs source instead of
  `kubernetes` when a standard service value was defined for the container.

- Fixes panic on concurrent map access in Kubernetes metadata tag collector.

- Fixed a bug that could potentially cause missing container tags for check metrics.

- Fix a potential panic on ECS when the ECS API is returning empty docker ID

- Fix systemd check id to handle multiple instances. The fix will make
  check id unique for each different instances.

- Fix missing tags on pods that were not seen with a running container yet.

- Fix snmp listener subnet loop to use correct subnet pointer
  when creating snmpJob object.

- Upgrade the embedded pip version to 20.3.3 to get a newer vendored version of urllib3.


.. _Release Notes_7.25.0_Other Notes:

Other Notes
-----------

- The Agent, Logs Agent and the system-probe are now compiled with Go ``1.14.12``

- Upgrade embedded ``libkrb5`` Kerberos library to v1.18.3. This version drops support for
  the encryption types marked as "weak" in the `docs of the library <https://web.mit.edu/kerberos/krb5-1.17/doc/admin/conf_files/kdc_conf.html#encryption-types>`_


.. _Release Notes_7.24.1:

7.24.1
======

.. _Release Notes_7.24.1_Bug Fixes:

Prelude
-------

Release on: 2020-12-17


Bug Fixes
---------

- Fix a bug when parsing the current version of an integration that prevented
  upgrading from an alpha or beta prerelease version.

- During a domain installation in a child domain, the Windows installer can now use a user from a parent domain.

- The Datadog Agent had a memory leak where some tags would be collected but
  never cleaned up after their entities were removed from a Kubernetes
  cluster due to their IDs not being recognized. This has now been fixed, and
  all tags are garbage collected when their entities are removed.


.. _Release Notes_7.24.1_Other Notes:

Other Notes
-----------

- Updated the shipped CA certs to latest (2020-12-08)

.. _Release Notes_7.24.0:

7.24.0 / 6.24.0
======

.. _Release Notes_7.24.0_Prelude:

Prelude
-------

Release on: 2020-12-03

- Please refer to the `7.24.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7240>`_ for the list of changes on the Core Checks


.. _Release Notes_7.24.0_Upgrade Notes:

Upgrade Notes
-------------

- tcp_queue_length check: the previous metrics reported by this check (``tcp_queue.rqueue.size``, ``tcp_queue.rqueue.min``, ``tcp_queue.rqueue.max``, ``tcp_queue.wqueue.size``, ``tcp_queue.wqueue.min``, ``tcp_queue.wqueue.max``) were generating too much data because there was one time series generated per TCP connection.
  Those metrics have been replaced by ``tcp_queue.read_buffer_max_usage_pct``, ``tcp_queue.write_buffer_max_usage_pct`` which are aggregating all the connections of a container.
  These metrics are reporting the maximum usage in percent (amount of data divided by the queue capacity) of the busiest buffer.
  Additionally, `only_count_nb_context` option from the `tcp_queue_length` check configuration has been removed and will be ignored from now on.


.. _Release Notes_7.24.0_New Features:

New Features
------------

- Added new configuration flag,
  system_probe_config.enable_conntrack_all_namespaces,
  false by default. When set to true, this will allow system
  probe to monitor conntrack entries (for NAT info) in all
  namespaces that are peers of the root namespace.

- Added JMX version and java runtime version to agent status page

- ``kubernetes_pod_annotations_as_tags`` (``DD_KUBERNETES_POD_ANNOTATIONS_AS_TAGS``) now support regex wildcards:
  ``'{"*":"<PREFIX>_%%annotation%%"}'`` can be used as value to collect all pod annotations as tags.
  ``kubernetes_node_labels_as_tags`` (``DD_KUBERNETES_NODE_LABELS_AS_TAGS``) now support regex wildcards:
  ``'{"*":"<PREFIX>_%%label%%"}'`` can be used as value to collect all node labels as tags.
  Note: ``kubernetes_pod_labels_as_tags`` (``DD_KUBERNETES_POD_LABELS_AS_TAGS``) supports this already.

- Listening for conntrack updates from all network namespaces
  (system_probe_config.enable_conntrack_all_namespaces flag) is now turned
  on by default


.. _Release Notes_7.24.0_Enhancement Notes:

Enhancement Notes
-----------------

- Expand pause container image filter

- Adds misconfig check for hidepid=2 option on proc mount.

- It's possible to ignore ``auto_conf.yaml`` configuration files using ``ignore_autoconf`` or ``DD_IGNORE_AUTOCONF``.
  Example: DD_IGNORE_AUTOCONF="redisdb kubernetes_state"

- APM: The trace-agent now automatically sets the GOMAXPROCS value in
  Linux containers to match allocated CPU quota, as opposed to the matching
  the entire node's quota.

- APM: Lowered CPU usage when using analytics.

- APM: Move UTF-8 validation from the span normalizer to the trace decoder, which reduces the number of times each distinct string will be validated to once, which is beneficial when the v0.5 trace format is used.

- Add the config `forwarder_retry_queue_payloads_max_size` which defines the
  maximum size in bytes of all the payloads in the forwarder's retry queue.

- When enabled, JMXFetch now logs to its own log file. Defaults to ``jmxfetch.log``
  in the default agent log directory, and can be configured with ``jmx_log_file``.

- Added UDS support for JMXFetch
  JMXFetch upgraded to `0.40.3 <https://github.com/DataDog/jmxfetch/releases/0.40.3>`_

- dogstatsd_mapper_profiles may now be defined as an environment variable DD_DOGSTATSD_MAPPER_PROFILES formatted as JSON

- Add orchestrator explorer related section into DCA Status

- Added byte count per log source and display it on the status page.

- APM: refactored the SQL obfuscator to be significantly more efficient.


.. _Release Notes_7.24.0_Deprecation Notes:

Deprecation Notes
-----------------

- IO check: device_blacklist_re has been deprecated in favor of device_exclude_re.

- The config options tracemalloc_whitelist and tracemalloc_blacklist have been
  deprecated in favor of tracemalloc_include and tracemalloc_exclude.


.. _Release Notes_7.24.0_Bug Fixes:

Bug Fixes
---------

- APM: Fix a bug where non-float64 numeric values in apm_config.analyzed_spans
  would disable this functionality.

- Disable stack protector on system-probe to make it buildable on the environments which stack protector is enabled by default.

  Some linux distributions like Alpine Linux enable stack protector by default which is not available on eBPF.

- Fix a panic in containerd if retrieved ociSpec is nil

- Fix random panic in Kubelet searchPodForContainerID due to concurrent modification of pod.Status.AllContainers

- Add retries to Kubernetes host tags retrievals, minimize the chance of missing/changing host tags every 30mins

- Fix rtloader build on strict posix environment, e.g. musl libc on Alpine Linux.

- Allows system_probe to be enabled without enabling network performance monitoring.

  Set ``network_config.enabled=false`` in your ``system-probe.yaml`` when running the system-probe without networks enabled.

- Fixes truncated output for status of compliance checks in Security Agent.

- Under some circumstances, the Agent would delete all tags for a workload if
  they were collected from different sources, such as the kubelet and docker,
  but deleted from only one of them. Now, the agent keeps track of tags per
  collector correctly.


.. _Release Notes_7.24.0_Other Notes:

Other Notes
-----------

- The utilities provided by the `sysstat` package have been removed: the ``iostat``,
  ``mpstat``, ``pidstat``, ``sar``, ``sadf``, ``cifsiostat`` and ``nfsiostat-sysstat``
  binaries have been removed from the packaged Agent. This has no effect on the
  behavior of the Agent and official integrations, but your custom checks may be
  affected if they rely on these embedded binaries.

- Activate security-agent service by default in the Linux packages of the Agent (RPM/DEB). The security-agent won't be started if the file /etc/datadog-agent/security-agent.yaml does not exist.


.. _Release Notes_7.23.1:

7.23.1 / 6.23.1
======

.. _Release Notes_7.23.1_Prelude:

Prelude
-------

Release on: 2020-10-21

.. _Release Notes_7.23.1_Bug Fixes:

Bug Fixes
---------

- The ``ec2_prefer_imdsv2`` parameter was ignored when fetching
  EC2 tags from the metadata endpoint. This fixes a misleading warning log that was logged
  even when ``ec2_prefer_imdsv2`` was left disabled in the Agent configuration.

- Support of secrets in JSON environment variables, added in `7.23.0`, is
  reverted due to a side effect (e.g. a string value of `"-"` would be loaded as a list). This
  feature will be fixed and added again in a future release.

- The Windows installer can now install on domains where the domain name is different from the Netbios name.


.. _Release Notes_7.23.0:

7.23.0 / 6.23.0
======

.. _Release Notes_7.23.0_Prelude:

Prelude
-------

Release on: 2020-10-06

- Please refer to the `7.23.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7230>`_ for the list of changes on the Core Checks


.. _Release Notes_7.23.0_Upgrade Notes:

Upgrade Notes
-------------

- Network monitoring: enable DNS stats collection by default.


.. _Release Notes_7.23.0_New Features:

New Features
------------

- APM: Decoding errors reported by the `datadog.trace-agent.receiver.error`
  and `datadog.trace_agent.normalizer.traces_dropped` contain more detailed
  reason tags in case of EOFs and timeouts.

- Running the agent flare with the -p flag now includes profiles
  for the trace-agent.

- APM: An SQL query obfuscation cache was added under the feature flag
  DD_APM_FEATURES=sql_cache. In most cases where SQL queries are repeated
  or prepared, this can significantly reduce CPU work.

- Secrets handles are not supported inside JSON value set through environment variables.
  For example setting a secret in a list
  `DD_FLARE_STRIPPED_KEYS='["ENC[auth_token_name]"]' datadog-agent run`

- Add basic support for UTF16 (BE and LE) encoding.
  It should be manually enabled in a log configuration using
  ``encoding: utf-16-be`` or ``encoding: utf-16-le`` other
  values are unsupported and ignored by the agent.


.. _Release Notes_7.23.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add new configuration parameter to allow 'GroupExec' permission on the secret-backend command.
  Set to 'true' the new parameter 'secret_backend_command_allow_group_exec_perm' to activate it.

- Add a map from DNS rcode to count of replies received with that rcode

- Enforces a size limit of 64MB to uncompressed sketch payloads (distribution metrics).
  Payloads above this size will be split into smaller payloads before being sent.

- APM: Span normalization speed has been increased by 15%.

- Improve the ``kubelet`` check error reporting in the output of ``agent status`` in the case where the agent cannot properly connect to the kubelet.

- Add `space_id`, `space_name`, `org_id` and `org_name` as tags to both autodiscovered containers as well as checks found through autodiscovery on Cloud Foundry/Tanzu.

- Improves compliance check status view in the security-agent status command.

- Include compliance benchmarks from github.com/DataDog/security-agent-policies in the Agent packages and the Cluster Agent image.

- Windows Docker image is now based on Windows Server Nano instead of Windows Server Core.

- Allow sending the GCP project ID under the ``project_id:`` host tag key, in addition
  to the ``project:`` host tag key, with the ``gce_send_project_id_tag`` config setting.

- Add `kubeconfig` to GCE excluded host tags (used on GKE)

- The cluster name can now be longer than 40 characters, however
  the combined length of the host name and cluster name must not
  exceed 254 characters.

- When requesting EC2 metadata, you can use IMDSv2 by turning
  on a new configuration option (``ec2_prefer_imdsv2``).

- When tailing logs from container in a kubernetes environment
  long lines (>16kB usually) that got split by the container
  runtime (docker & containerd at least) are now reassembled
  pending they do not exceed the upper message length limit
  (256kB).

- Move the cluster-id ConfigMap creation, and Orchestrator
  Explorer controller instantiation behind the orchestrator_explorer
  config flag to avoid it failing and generating error logs.

- Add caching for sending kubernetes resources for live containers

- Agent log format improvement: logs can have kv-pairs as context to make it easier to get all logs for a given context
  Sample: 2020-09-17 12:17:17 UTC | CORE | INFO | (pkg/collector/runner/runner.go:327 in work) | check:io | Done running check

- The CRI check now supports container exclusion based on container name, image and kubernetes namespace.

- Added a network_config config to the system-probe that allows the
  network module to be selectively enabled/disabled. Also added a
  corresponding DD_SYSTEM_PROBE_NETWORK_ENABLED env var.  The network module
  will only be disabled if the network_config exists and has enabled set to
  false, or if the env var is set to false.  To maintain compatibility with
  previous configs, the network module will be enabled in all other cases.

- Log a warning when a log file is rotated but has not finished tailing the file.

- The NTP check now uses the cloud provider's recommended NTP servers by default, if the Agent
  detects that it's running on said cloud provider.


.. _Release Notes_7.23.0_Deprecation Notes:

Deprecation Notes
-----------------

- `process_config.orchestrator_additional_endpoints` and `process_config.orchestrator_dd_url` are deprecated in favor of:
  `orchestrator_explorer.orchestrator_additional_endpoints` and `orchestrator_explorer.orchestrator_dd_url`.


.. _Release Notes_7.23.0_Bug Fixes:

Bug Fixes
---------

- Allow `agent integration install` to work even if the datadog agent
  configuration file doesn't exist.
  This is typically the case when this command is run from a Dockerfile
  in order to build a custom image from the datadog official one.

- Implement variable interpolation in the tagger when inferring the standard tags
  from the ``DD_ENV``, ``DD_SERVICE`` and ``DD_VERSION`` environment variables

- Fix a bug that was causing not picking checks and logs for containers targeted
  by container-image-based autodiscovery. Or picking checks and logs for
  containers that were not targeted by container-image-based autodiscovery.
  This happened when several image names were pointing to the same image digest.

- APM: Allow digits in SQL literal identifiers (e.g. `1sad123jk`)

- Fixes an issue with not always reporting ECS Fargate task_arn tag due to a race condition in the tag collector.

- The SUSE SysVInit service now correctly starts the Agent as the
  dd-agent user instead of root.

- APM: Allow double-colon operator in SQL obfuscator.

- UDP packets can be sent in two ways. In the "connected" way, a `connect` call is
  made first to assign the remote/destination address, and then packets get sent with the `send`
  function or `sendto` function with destination address set to NULL. In the "unconnected" way,
  packets get sent using `sendto` function with a non NULL destination address. This fix addresss
  a bug where network stats were not being generated for UDP packets sent using the "unconnected"
  way.

- Fix the Windows systray not appearing sometimes (bug introduced with 6.20.0).

- The Chocolatey package now uses a fixed URL to the MSI installer.

- Fix logs tagging inconsistency for restarted containers.

- On macOS, in Agent v6, the unversioned python binaries in
  ``/opt/datadog-agent/embedded/bin`` (example: ``python``, ``pip``) now correctly
  point to the Python 2 binaries.

- Fix truncated cgroup name on copy with bpf_probe_read_str in OOM kill and TCP queue length checks.

- Use double-precision floats for metric values submitted from Python checks.

- On Windows, the ddtray executable now has a digital signature

- Updates the logs package to get the short image name from Kubernetes ContainerSpec, rather than ContainerStatus.
  This works around a known issue where the image name in the ContainerStatus may be incorrect.

- On Windows, the Agent now responds to control signals from the OS and shuts down gracefully.
  Coincidentally, a Windows Agent Container will now gracefully stop when receiving the stop command.


.. _Release Notes_7.23.0_Other Notes:

Other Notes
-----------

- All Agents binaries are now compiled with Go  ``1.14.7``

- JMXFetch upgraded from `0.38.2 <https://github.com/DataDog/jmxfetch/releases/0.38.2>`_
  to `0.39.1 <https://github.com/DataDog/jmxfetch/releases/0.39.1>`_

- Move the orchestrator related settings `process_config.orchestrator_additional_endpoints` and
  `process_config.orchestrator_dd_url` into the `orchestrator_explorer` section.


.. _Release Notes_7.22.1:

7.22.1 / 6.22.1
======

.. _Release Notes_7.22.1_Prelude:

Prelude
-------

Release on: 2020-09-17

- Please refer to the `7.22.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7221>`_ for the list of changes on the Core Checks

.. _Release Notes_7.22.1_Bug Fixes:

Bug Fixes
---------

- Define a default logs file (security-agent.log) for the security-agent.

- Fix segfault when listing Garden containers that are in error state.

- Do not activate security-agent service by default in the Linux packages of the Agent (RPM/DEB). The security-agent was already properly starting and exiting if not activated in configuration.


.. _Release Notes_7.22.0:

7.22.0 / 6.22.0
======

.. _Release Notes_7.22.0_Prelude:

Prelude
-------

Release on: 2020-08-25

- Please refer to the `7.22.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7220>`_ for the list of changes on the Core Checks


.. _Release Notes_7.22.0_New Features:

New Features
------------

- Implements agent-side compliance rule evaluation in security agent using expressions.

- Add IO operations monitoring for Docker check (docker.io.read/write_operations)

- Track TCP connection churn on system-probe

- The new Runtime Security Agent collects file integrity monitoring events.
  It is disabled by default and only available for Linux for now.

- Make security-agent part of automatically started agents in RPM/DEB/etc. packages (will do nothing and exit 0 by default)

- Add support for receiving and processing SNMP traps, and forwarding them as logs to Datadog.

- APM: A new trace ingestion endpoint was introduced at /v0.5/traces which supports a more compact payload format, greatly
  improving resource usage. The spec for the new wire format can be viewed `here <https://github.com/DataDog/datadog-agent/blob/7.22.0/pkg/trace/api/version.go#L21-L69>`_.
  Tracers supporting this change will automatically use the new endpoint.

.. _Release Notes_7.22.0_Enhancement Notes:

Enhancement Notes
-----------------

- Adds a gauge for `system.mem.slab_reclaimable`. This is part of slab
  memory that might be reclaimed (i.e. caches). Datadog 7.x adds
  `SReclaimable` memory, if available on the system, to the
  `system.mem.cached` gauge by default. This may lead to inconsistent
  metrics for clients migrating from Datadog 5.x, where
  `system.mem.cached` didn't include `SReclaimable` memory. Adding a gauge
  for `system.mem.slab_reclaimable` allows inverse calculation to remove
  this value from the `system.mem.cached` gauge.

- Expand GCR pause container image filter

- Kubernetes events for pods, replicasets and deployments now have tags that match the metrics metadata.
  Namely, `pod_name`, `kube_deployment`, `kube_replicas_set`.

- Enabled the collection of the kubernetes resource requirements (requests and limits)
  by bumping the agent-payload dep. and collecting the resource requirements.

- Implements resource fallbacks for complex compliance check assertions.

- Add system.cpu.num_cores metric with the number of CPU cores (windows/linux)

- compliance: Add support for Go custom compliance checks and implement two for CIS Kubernetes

- Make DSD Mapper also map metrics that already contain tags.

- If the retrieval of the AWS EC2 instance ID or hostname fails, previously-retrieved
  values are now sent, which should mitigate host aliases flapping issues in-app.

- Increase default timeout on AWS EC2 metadata endpoints, and make it configurable
  with ``ec2_metadata_timeout``

- Add container incl./excl. lists support for ECS Fargate (process-agent)

- Adds support for a heap profile and cpu profile (of configurable length) to be created and
  included in the flare.

- Upgrade embedded Python 3 to 3.8.5. Link to Python 3.8 changelog: https://docs.python.org/3/whatsnew/3.8.html

  Note that the Python 2 version shipped in Agent v6 continues to be version 2.7.18 (unchanged).

- Upgrade pip to v20.1.1. Link to pip 20.1.1 changelog: https://pip.pypa.io/en/stable/news/#id54

- Upgrade pip-tools to v5.3.1. Link to pip-tools 5.3.1 changelog: https://github.com/jazzband/pip-tools/blob/master/CHANGELOG.md

- Introduces support for resolving pathFrom from in File and Audit checks.

- On Windows, always add the user to the required groups during installation.

- APM: A series of changes to internal algorithms were made which reduced CPU usage between 20-40% based on throughput.


.. _Release Notes_7.22.0_Bug Fixes:

Bug Fixes
---------

- Allow integration commands to work for pre-release versions.

- [Windows] Ensure ``PYTHONPATH`` variable is ignored correctly when initializing the Python runtime.

- Enable listening for conntrack info from all namespaces in system probe

- Fix cases where the resolution of secrets in integration configs would not
  be performed for autodiscovered containers.

- Fixes submission of containers blkio metrics that may modify array after being already used by aggregator. Can cause missing tags on containerd.* metrics

- Restore support of JSON-formatted lists for configuration options passed as environment variables.

- Don't allow pressing the disable button on checks twice.

- Fix `container_include_metrics` support for all container checks

- Fix a bug where the Agent disables collecting tags when the
  cluster checks advanced dispatching is enabled in the Daemonset Agent.

- Fixes a bug where the ECS metadata endpoint V2 would get queried even though it was not configured
  with the configuration option `cloud_provider_metadata`.

- Fix a bug when a kubernetes job has exited after some time the tagger does not update it even if it did change its state.

- Fixes the Agent failing to start on sysvinit on systems with dpkg >= 1.19.3

- The agent was collecting docker container logs (metrics)
  even if they are matching `DD_CONTAINER_EXCLUDE_LOGS`
  (resp. `DD_CONTAINER_EXCLUDE_METRICS`)
  if they were started before the agent. This is now fixed.

- Fix a bug where the Agent would not remove tags for pods that no longer
  exist, potentially causing unbounded memory growth.

- Fix pidfile support on security-agent

- Fixed system-probe not working on CentOS/RHEL 8 due to our custom SELinux policy.
  We now install the custom policy only on CentOS/RHEL 7, where the system-probe is known
  not to work with the default. On other platform the default will be used.

- Stop sending payload for Cloud Foundry applications containers that have no `container_name` tag attached to avoid them showing up in the UI with empty name.


.. _Release Notes_7.22.0_Other Notes:

Other Notes
-----------

- APM: datadog.trace_agent.receiver.* metrics are now also tagged by endpoint_version


.. _Release Notes_7.21.1:

7.21.1
======

.. _Release Notes_7.21.1_Prelude:

Prelude
-------

Release on: 2020-07-22

.. _Release Notes_7.21.1_Bug Fixes:

Bug Fixes
---------

- JMXFetch upgraded to `0.38.2 <https://github.com/DataDog/jmxfetch/releases/0.38.2>`_ to fix Java 7 support.
- Fix init of security-agent - exit properly when no feature requiring it is activated and avoid conflicting with core agent port bindings.

.. _Release Notes_7.21.0:

7.21.0 / 6.21.0
======

.. _Release Notes_7.21.0_Prelude:

Prelude
-------

Release on: 2020-07-16

- Please refer to the `7.21.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7210>`_ for the list of changes on the Core Checks


.. _Release Notes_7.21.0_Upgrade Notes:

Upgrade Notes
-------------

- APM: The maximum allowed payload size by the agent was increased
  from 10MB to 50MB. This could result in traffic increases for
  users which were affected by this issue.

- APM: The maximum connection limit over a 30s period was removed.
  This can result in an increase of tracing data for users that were
  affected by this limitation.


.. _Release Notes_7.21.0_New Features:

New Features
------------

- Add support of new DatadogMetric CRD in DCA. Allows to autoscale based on any valid Datadog query.

- Add packages scripts for dogstatsd that have the same features as the agent: create
  symlink for binary, create dd-agent user and group, setup the service and cleanup
  those when uninstalling.

- Adds OOM Kill probe to ebpf package and corresponding corecheck to the agent.

- The Datadog IoT Agent is now available for 32 bit ARM architecture (armv7l/armhf).

- Add Compliance agent in Cluster Agent to monitor Kubernetes objects

- Add `docker.cpu.limit` and `containerd.cpu.limit` metrics, reporting maximum cpu time (hz or ns) available for each container based on their limits. (Only supported on Linux)

- Addition of a gRPC server and a hostname resolution endpoint,
  including a grpc-gateway that exposes said endpoint as a REST
  service.

- Adding a 'log_format_rfc3339' option to use the RFC3339 format for the log
  time.

- Compliance Agent implementing scheduling of compliance checks for Docker and Kubernetes benchmarks.

- Expose agent's sql obfuscation to python checks via new `datadog_agent.obfuscate_sql` method

- Support installing non-core integrations with the ``integration`` command,
  such as those located in the ``integrations-extras`` repository.


.. _Release Notes_7.21.0_Enhancement Notes:

Enhancement Notes
-----------------

- The Agent ``status`` command now includes the flavor
  of the Agent that is running.

- The Agent GUI now includes the flavor
  of the Agent that is running.

- Adds Tagger information to Datadog Agent flare for support investigations.

- Add a static collector in the tagger package for tags that do not change after pod start (such as
  those from an environment variable).

- Add ``autodiscovery_subnet`` to available SNMP template extra configs

- When enabling `collect_ec2_tags` or `collect_gce_tags` option, EC2/GCE tags
  are now cached to avoid missing tags when user exceed his AWS/GCE quotas.

- Chocolatey package can be installed on Domain Controller

- The Agent now collects the Availability Zone a Fargate Task (using platform
  version 1.4 or later) is running in as an "availability_zone" tag.

- Enabled the collection of the init-containers by bumping the agent-payload dep. and collecting the init-containers.

- The Agent now collects recommended "app.kubernetes.io" Kubernetes labels as
  tags by default, and exposes them under a "kube_app" prefix.

- Docker and Containerd checks now support filtering containers by kube_namespace.

- Add support for sampling to distribution metrics

- Flare now includes the permission information for parents of config and log file directories.

- Collect processes namespaced PID.

- You can now enable or disable the dogstatsd-stats troubleshooting feature at
  runtime using the ``config set dogstatsd_stats`` command of the Agent.

- API Keys are now sanitized for `logs_config` and `additional_endpoints`.

- Upgrade gosnmp to support more authentication and privacy protocols
  for v3 connections.

- Use the standard tag 'service' as a log collection attribute for container's logs
  collected from both kubernetes and docker log sources.

- `agent check` returns non zero exit code when trace malloc is enabled (`tracemalloc_debug: true`) when using python 2

- Added the checksum type to the checksum key itself, as it is deprecated to have a separate
  checksum_type key.

- Add ``lowercase_device_tag`` option to the system ``io`` core check on Windows.
  When enabled, sends metrics with a lowercased ``device`` tag, which is consistent with the
  ``system.io.*`` metrics of Agent v5 and the ``system.disk.*`` metrics of all Agent
  versions.


.. _Release Notes_7.21.0_Bug Fixes:

Bug Fixes
---------

- Fix missing values from cluster-agent status command.

- Add missing ``device_name`` tag in iostats_pdh

- Fixes an issue where DD_TAGS were not applied to EKS Fargate pods and containers.

- Add ``freetds`` linux dep needed for SQL Server to run in Docker Agent.

- APM : Fix parsing of non-ASCII numerals in the SQL obfuscator. Previously
  unicode characters for which unicode.IsDigit returns true could cause a
  hang in the SQL obfuscator

- APM: correctly obfuscate AUTH command.

- Dogstatsd standalone: when running on a systemd-based system, do not stop
  Dogstatsd when journald is stopped or restarted.

- Fix missing logs and metrics for docker-labels based autodiscovery configs after container restart.

- Fix bugs introduced in 7.20.0/6.20.0 in the Agent 5 configuration import command:
  the command would not import some Agent config settings, including ``api_key``,
  and would write some Docker & Kubernetes config settings to wrongly-located files.

- Fixes tag extraction from Kubernetes pod labels when using patterns on
  certain non-alphanumeric label names (e.g. app.kubernetes.io/managed-by).

- Fixes the `/ready` health endpoint on the cluster-agent.

  The `/ready` health endpoint was reporting 200 at the cluster-agent startup and was then, permanently reporting 500 even though the cluster-agent was experiencing no problem.
  In the body of the response, we could see that a `healthcheck` component was failing.
  This change fixes this issue.

- This fix aims to cover the case when the agent is running inside GKE with workload identity enabled.
  If workload identity is enabled, access to /instance/name is forbidden, resulting into an empty host alias.

- Fix hostname resolution issue preventing the Process and APM agents from picking
  up a valid hostname on some containerized environments

- Fix a bug which causes certain configuration options to be ignored by the ``process-agent`` in the presence of a ``system-probe.yaml``.

- Process agent and system probe now correctly accept multiple API keys per endpoint.

- The ``device_name`` tag is not used anymore to populate the ``Device`` field of a series. Only the ``device`` tag is considered.

- Fixes problem on Windows where ddagentuser home directory is left behind.

- Revert upgrade of GoSNMP and addition of extra authentication protocols.

- Add support for examining processes inside Docker containers running under
  systemd cgroups. This also reduces agent logging volume as it's able to
  capture those statistics going forward.

- APM: The agent now exits with code 0 when the API key is not specified. This is so to prevent the Windows SCM
  from restarting the process.


.. _Release Notes_7.21.0_Other Notes:

Other Notes
-----------

- All Agents binaries are now compiled with Go ``1.13.11``.

- In Debug mode, DogStatsD log a warning message when a burst of metrics is detected.

- JMXFetch upgraded to `0.38.0 <https://github.com/DataDog/jmxfetch/releases/0.38.0>`_

- JQuery, used in the web-based agent GUI, has been upgraded to 3.5.1


.. _Release Notes_7.20.2:

7.20.2
======

.. _Release Notes_7.20.2_Prelude:

Prelude
-------

Release on: 2020-06-17

- Please refer to the `7.20.2 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7202>`_ for the list of changes on the Core Checks


.. _Release Notes_7.20.1:

7.20.1
======

.. _Release Notes_7.20.1_Prelude:

Prelude
-------

Release on: 2020-06-11

- Please refer to the `7.20.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7201>`_ for the list of changes on the Core Checks


.. _Release Notes_7.20.0:

7.20.0 / 6.20.0
======

.. _Release Notes_7.20.0_Prelude:

Prelude
-------

Release on: 2020-06-11

- Please refer to the `7.20.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7200>`_ for the list of changes on the Core Checks


.. _Release Notes_7.20.0_New Features:

New Features
------------

- Pod and container tags autodiscovered via pod annotations
  now support multiple values for the same key.

- Install script creates ``install_info`` report

- Agent detects ``install_info`` report and sends it through Host metadata

- Adding logic to get standard ``service`` tag from Pod Metadata Labels.

- APM: A new endpoint was added which helps augment and forward profiles
  to Datadog's intake.

- APM: Information about APM is now included in the agent's status
  output (both in the GUI and in the 'agent status' command).

- Introducing the 'cloud_provider_metadata' option in the Agent configuration
  to restrict which cloud provider metadata endpoints will be queried.

- Add collector for Garden containers running applications in CloudFoundry environment
  to view them in the live container list and container map.

- JMXFetch (helper for JMX checks) is now restarted if it crashes on Windows.

- Add scaffold for security/compliance agent CLI.

- ``container_exclude_metrics`` and ``container_include_metrics`` can be used to filter metrics collection for autodiscovered containers.
  ``container_exclude_logs`` and ``container_include_logs`` can be used to filter logs collection for autodiscovered containers.

- Support SNMP autodiscovery via a new configuration listener, with new
  template variables.

- Support Tencent Cloud provider.


.. _Release Notes_7.20.0_Enhancement Notes:

Enhancement Notes
-----------------

- When installing the Agent using Chocolatey,
  information about the installation is saved for
  diagnostic and telemetry purposes.

- The Agent's flare now includes information about the method used
  to install the Agent.

- Ignore AKS pause containers hosted in the aksrepos.azurecr.io
  container registry.

- On Linux and MacOS, add a new ``device_name`` tag on IOstats and disk checks.

- Windows installer can use the command line key ``HOSTNAME_FQDN_ENABLED`` to set the config value of ``hostname_fqdn``.

- Add missing ``device_name`` tags on docker, containerd and network checks.
  Make series manage ``device_name`` tag if ``device`` is missing.

- Support custom tagging of docker container data via an autodiscovery "tags"
  label key.

- Improved performances in metric aggregation logic.
  Use 64 bits context keys instead of 128 bits in order to benefit from better
  performances using them as map keys (fast path methods) + better performances
  while computing the hash thanks to inlining.

- Count of DNS responses with error codes are tracked for each connection.

- Latency of successful and failed DNS queries are tracked for each connection.Queries that time out are also tracked separately.

- Enrich dogstatsd metrics with task_arn tag if
  DD_DOGSTATSD_TAG_CARDINALITY=orchestrator.

- More pause containers from ``ecr``, ``gcr`` and ``mcr`` are excluded automatically by the Agent.

- Improve cluster name auto-detection on Azure AKS.

- APM: Improve connection reuse with HTTP keep-alive in
  trace agent.

- Increase default timeout to collect metadata from GCE endpoint.

- Use insertion sort in the aggregator context keys generator as it provides
  better performances than the selection sort. In cases where the insertion
  sort was already used, improved its threshold selecting between it and Go
  stdlib sort.

- Expose distinct endpoints for liveness and readiness probes.

  * The liveness probe (``/live``) fails in case of unrecoverable error that deserve
    an agent restart. (Ex.: goroutine deadlock or premature exit)
  * The readiness probe (``/ready``) fails in case of recoverable errors or errors
    for which an agent restart would be more nasty than useful
    (Ex.: the forwarder fails to connect to DataDog)

- Exclude automatically pause containers for OpenShift, EKS and AKS Windows

- Introduce ``kube_cluster_name`` and ``ecs_cluster_name`` tags in addition to ``cluster_name``.
  Add the possibility to stop sending the ``cluster_name`` tag using the parameter ``disable_cluster_name_tag_key`` in Agent config.
  The Agent keeps sending ``kube_cluster_name`` and `ecs_cluster_name` tags regardless of `disable_cluster_name_tag_key`.

- Configure additional process and orchestrator endpoints by environment variable.

- The process agent can be canfigured to collect containers
  from multiple sources (e.g kubelet and docker simultaneously).

- Upgrading the embedded Python 2 to the latest, and final, 2.7.18 release.

- Improve performance of system-probe conntracker.

- Throttle netlink socket on workloads with high connection churn.


.. _Release Notes_7.20.0_Deprecation Notes:

Deprecation Notes
-----------------

- ``container_exclude`` replaces ``ac_exclude``.
  ``container_include`` replaces ``ac_include``.
  ``ac_exclude`` and ``ac_include`` will keep being supported but the Agent ignores them
  in favor of ``container_exclude`` and ``container_include`` if they're defined.


.. _Release Notes_7.20.0_Bug Fixes:

Bug Fixes
---------

- APM: Fix a small programming error causing the "superfluous response.WriteHeader call" warning.

- Fixes missing container stats in ECS Fargate 1.4.0.

- Ensure Python checks are always garbage-collected after they're unscheduled
  by AutoDiscovery.

- Fix for autodiscovered checks not being rescheduled after container restart.

- On Windows, fix calculation of the ``system.swap.pct_free`` metric.

- Fix a bug in the file tailer on Windows where the log-agent would keep a
  lock on the file preventing users from renaming the it.


.. _Release Notes_7.20.0_Other Notes:

Other Notes
-----------

- Upgrade embedded ntplib to ``0.3.4``

- JMXFetch upgraded to `0.36.2 <https://github.com/DataDog/jmxfetch/releases/0.36.2>`_

- Rebranded puppy agent as iot-agent.


.. _Release Notes_7.19.2:

7.19.2 / 6.19.2
======

.. _Release Notes_7.19.2_Prelude:

Prelude
-------

Release on: 2020-05-12

- Please refer to the `7.19.2 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7192>`_ for the list of changes on the Core Checks


.. _Release Notes_7.19.1:

7.19.1
======

.. _Release Notes_7.19.1_Prelude:

Prelude
-------

Release on: 2020-05-04

This release is only an Agent v7 release, as Agent v6 is not affected by the undermentioned bug.

.. _Release Notes_7.19.1_Bug Fixes:

Bug Fixes
---------

- Fix panic in the dogstatsd standalone package when running in a containerized environment.


.. _Release Notes_7.19.0:

7.19.0 / 6.19.0
======

.. _Release Notes_7.19.0_Prelude:

Prelude
-------

Release on: 2020-04-30

- Please refer to the `7.19.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7190>`_ for the list of changes on the Core Checks


.. _Release Notes_7.19.0_Upgrade Notes:

Upgrade Notes
-------------

- Default logs-agent to use HTTPS with compression when possible.
  Starting from this version, the default transport is HTTPS with compression instead of TCP.
  The usage of TCP is kept in the following cases:
    * logs_config.use_tcp is set to true
    * logs_config.socks5_proxy_address is set, because socks5 proxies are not yet supported in HTTPS with compression
    * HTTPS connectivity test has failed: at agent startup, an HTTPS test request is sent to determine if HTTPS can be used

  To force the use of TCP or HTTPS with compression, logs_config.use_tcp or logs_config.use_http can be set to true, respectively.


.. _Release Notes_7.19.0_New Features:

New Features
------------

- The Agent is now available on Chocolatey for Windows

- Add ``--full-sketches`` option to agent check command that displays bins information

- Support logs collection from Kubernetes log files with old Kubernetes versions (< v1.10).

- Expose the new JMXFetch rate with metrics method to test JMX based checks.

- The ``ac_include`` and ``ac_exclude`` auto-discovery parameters now support the
  ``kube_namespace:`` prefix to collect or discard logs and metrics for whole namespaces
  in addition to the ``name:`` and ``image:`` prefixes to filter on container name and image name.

- EKS Fargate containers now appear in the live containers view.
  All processes running inside the EKS Fargate Pod appear in the live processes view
  when `shareProcessNamespace` is enabled in the Pod Spec.

- Add the ability to change log_level at runtime. The agent command
  has been extended to support new operation. For example to set
  the log_level to debug the following command should be used:
  ``agent config set log_level debug``, all runtime-configurable
  settings can be listed using ``agent config list-runtime``. The
  log_level may also be fetched using the ``agent config get log_level``
  command. Additional runtime-editable setting can easily be added
  by following this implementation.

- The ``system-probe`` classifies UDP connections as incoming or outgoing.


.. _Release Notes_7.19.0_Enhancement Notes:

Enhancement Notes
-----------------

- Adds a new config option to the systemd core check. It adds the ability to provide a custom
  mapping from a unit substate to the service check status.

- The systemd core check now collects and submits the systemd version as check metadata.

- Add ``host_provider_id`` tag to Kubernetes events; for AWS instances this is unique in
  contrast to the Kubernetes nodename currently provided with the ``host`` tag.

- On Windows, now reports system.io.r_await and system.io.w_await.
  Metrics are reported from the performance monitor "Avg. Disk sec/Read" and
  "Avg. Disk sec/Write" metrics.

- Allow setting ``is_jmx`` at the instance level, thereby enabling integrations
  to utilize JMXFetch and Python/Go.

- The authentication token file is now only created
  when the agent is launched with the ``agent start`` command
  It prevents command such as ``agent status`` to create
  an authentication token file owned by a wrong user.

- Count of successful DNS responses are tracked for each connection.

- Network information is collected when the agent is running in docker (host mode only).

- Make sure we don't recognize ``sha256:...`` as a valid image name and add fallback to
  .Config.Image in case it's impossible to map ``sha256:...`` to a proper image name

- Extract env, version and service tags from Docker containers

- Extract env, version and service tags from ECS Fargate containers

- Extract env, version and service tags from kubelet

- Log configurations of type ``file`` now accept a new parameter that allows
  to specify whether a log shall be tailed from the beginning
  or the end. It aims to allow whole log collection, including
  events that may occur before the agent first starts. The
  parameter is named ``start_position`` and it can be set to
  ``end`` or ``beginning``, the default value is ``end``.

- Resolve Docker image name using config.Image in the case of multiple image RepoTags

- The agent configcheck command output now scrubs sensitive
  data and prevents API keys, password, token, etc. to
  appear in the console.

- Errors that arise while loading checks configuration
  files are now send with metadata along with checks
  loading errors and running errors so they will show
  up on the infrastructure list in the DataDog app.

- Remove cgroup deps from Docker utils, allows to implement several backends for Docker utils (i.e. Windows)


.. _Release Notes_7.19.0_Bug Fixes:

Bug Fixes
---------

- On Windows, for Python3, add additional C-runtime DLLs to fix missing dependencies (notably for jpype).

- Fix 'check' command segfault when running for more than 1 hour (which could
  happen when using the '-b' option to set breakpoint).

- Fix panic due to concurrent map access in Docker AD provider

- Fix the ``flare`` command not being able to be created for the non-core agents (trace,
  network, ...) when running in a separated container, such as in Helm. A new
  option, ``--local``, has been added to the ``flare`` command to force the
  creation of the archive using the local filesystem and not the one where
  the core agent process is in.

- Fix logs status page section showing port '0' being used when using the
  default HTTPS URL. The status page now show 443.

- Fix S6 behavior when the core agent dies.
  When the core agent died in a multi-process agent container managed by S6,
  the container stayed in an unhealthy half dead state.
  S6 configuration has been modified so that it will now exit in case of
  core agent death so that the whole container will exit and will be restarted.

- On Windows, fixes Process agent memory leak when obtaining process arguments.

- When a DNS name with ".local" is specifed in the parameter DDAGENTUSER_NAME, the correctly finds the corresponding domain.

- Fix an issue where ``conf.yaml.example`` can be missing from ``Add a check`` menu in the Web user interface.

- process-agent and system-probe now clean up their PID files when exiting.

- When the HTTPS transport is used to send logs, send the sourcecategory as the ``sourcecategory:`` tag
  instead of ``ddsourcecategory:``, for consistency with other transports.


.. _Release Notes_7.19.0_Other Notes:

Other Notes
-----------

- All Agents binaries are now compiled with Go ``1.13.8``

- JMXFetch upgraded to 0.36.1. See `0.36.1 <https://github.com/DataDog/jmxfetch/releases/0.36.1>`_
  and `0.36.0 <https://github.com/DataDog/jmxfetch/releases/0.36.0>`_

- The ``statsd_metric_namespace`` option now ignores the following metric
  prefixes: ``airflow``, ``confluent``, ``hazelcast``, ``hive``, ``ignite``,
  ``jboss``, ``sidekiq``


.. _Release Notes_7.18.1:

7.18.1
======

.. _Release Notes_7.18.1_Bug Fixes:

Bug Fixes
---------

- Fix conntrack issue where a large batch of deletion events was killing
  the goroutine polling the netlink socket.

- On Debian and Ubuntu-based systems, remove system-probe SELinux policy
  to prevent install failures.

.. _Release Notes_7.18.0:

7.18.0 / 6.18.0
======

.. _Release Notes_7.18.0_Prelude:

Prelude
-------

Release on: 2020-03-13

- Please refer to the `7.18.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7180>`_ for the list of changes on the Core Checks


.. _Release Notes_7.18.0_Upgrade Notes:

Upgrade Notes
-------------

- APM: Traces containing spans without an operation name will automatically
  be assigned the "unnamed_span" name (previously "unnamed-span").

- On MacOS, the Aerospike integration is no longer available since version 3.10
  of the aerospike-client-python library is not yet available on this platform.

- On MacOS, the IBM WAS integration is no longer available since it
  relies on the lxml package which currently doesn't pass Apple's
  notarization tests.

- On Windows, the embedded Python will no longer use the PYTHONPATH
  environment variable, restricting its access to the Python packages
  installed with the Agent. Set windows_use_pythonpath to true to keep
  the previous behavior.


.. _Release Notes_7.18.0_New Features:

New Features
------------

- Adding new "env" top level config option. This will be added to the host
  tags and propagated to the trace agent.

- Add SystemD integration support for SUSE.

- APM: Add support for calculating trace sublayer metrics for measured spans.

- APM: Add support for computing trace statistics on user-selected spans.

- APM: add support for `version` as another tag in trace metrics.

- Add docker.uptime, cri.uptime, and containerd.uptime metrics for all containers

- Add a warning in the logs-agent section of the agent status to incite users to switch over HTTP transport.

- Send a tag for any ``service`` defined in the ``init_config`` or
  ``instances`` section of integration configuration, with the latter
  taking precedence. This applies to metrics, events, and service checks.


.. _Release Notes_7.18.0_Enhancement Notes:

Enhancement Notes
-----------------

- The min_collection_interval check setting has been
  relocated since Agent 6/7 release. The agent import
  command now include in the right section this setting
  when importing configuration from Agent 5.

- Add new config parameter (dogstatsd_entity_id_precedence) to enable DD_ENTITY_ID
  presence check when enriching Dogstatsd metrics with tags.

- Add an option to exclude log files by name when wildcarding
  directories. The option is named ``exclude_paths``, it can be
  added for each custom log collection configuration file.
  The option accepts a list of glob.

- The status output now shows checks' last execution date
  and the last successful one.

- On debian- and rhel-based systems, system-probe is now set up so that
  it can run in SELinux-enabled environments.

- On Windows, a step to set the ``site`` parameter has been added
  to the graphical installer.

- Added support for inspecting DNS traffic received over TCP to gather DNS information.

- Review the retry strategy used by the agent to connect to external services like docker, kubernetes API server, kubelet, etc.
  In case of failure to connect to them, the agent used to retry every 30 seconds 10 times and then, to give up.
  The agent will now retry after 1 second. It will then double the period between two consecutive retries each time, up to 5 minutes.
  So, After 10 minutes, the agent will keep on retrying every 5 minutes instead of completely giving up after 5 minutes.
  This change will avoid to have to restart the agent if it started in an environment that remains degraded for a while (docker being down for several minutes for example.)

- Adds message field to the ComponentStatus check of kube_apiserver_controlplane.up
  service check.

- Add a config option ``ec2_use_windows_prefix_detection`` to use the EC2 instance id for Windows hosts on EC2.

- Templates used for the agent status command are now
  embedded in the binary at compilation time and thus
  original template files are not required anymore at
  runtime.

- Upgrade ``pip-tools`` and ``wheel`` dependencies for Python 2.

- Improve interpolation performance during conversion from Prometheus and
  OpenMetrics histograms to ddsketch

- Allow sources for the Logs Agent to fallback to the ``service``
  defined in the ``init_config`` section of integration configuration
  to match the global tag that will be emitted.

- Stop doing HTML escaping on agent status command output
  in order to properly display all non-alphanumeric
  characters.

- Upgrade embedded Python 3 to 3.8.1. Link to Python 3.8 changelog: https://docs.python.org/3/whatsnew/3.8.html

  Note that the Python 2 version shipped in Agent v6 continues to be version 2.7.17 (unchanged).

- Removing an RPM of the Datadog Agent will no longer throw missing files warning.

- The agent config command output now scrubs sensitive
  data and prevents API keys, password, token, etc. from
  appearing in the console.

- Add support for the EC2 instance metadata service
  (IMDS) v2 that requires to get a token before any
  metadata query. The agent will still issue
  unauthenticated request first (IMDS v1) before
  switching to token-based authentication (IMDS
  v2) if it fails.

- system-probe no longer needs to be enabled/started separately through systemctl


.. _Release Notes_7.18.0_Bug Fixes:

Bug Fixes
---------

- The `submit_histogram_bucket` API now accepts long integers as input values.

- ignore "origin" tags if the 'dd.internal.entity_id' tag is present in dogstatsd metrics.

- On Windows 64 bit, fix calculation of number of CPUS to handle
  machines with more than 64 CPUs.

- Make ``systemd`` core check handle gracefully missing ``SystemState`` attribute.

- Ignore missing docker label com.datadoghq.ad.check_names instead of showing error logs.

- The `jmx` and `check jmx` command will now properly use the loglevel provided
  with the deprecated `--log-level` flag or the `DD_LOG_LEVEL` environment var if any.

- Fix docker logs when the tailer receives a io.EOF error during a file rotation.

- Fix process-agent potentially dividing by zero when no containers are found.

- Fix process-agent not respecting logger configuration during startup.


.. _Release Notes_7.18.0_Other Notes:

Other Notes
-----------

- Errors mentioning the authentication token are now more specific and
  won't be obfuscated anymore.

- Upgrade embedded openssl to ``1.1.1d``, pyopenssl ``19.0.0`` and
  postgresql client lib to ``9.4.25``.

- Add the Go version used to build Dogstatsd in its `version` command.

- Update `s6-overlay` to `v1.22.1.0` in docker images

- JMXFetch upgraded to `0.35.0 <https://github.com/DataDog/jmxfetch/releases/0.35.0>`_

- Following the upgrade to Python 3.8, the Datadog Agent version ``>= 6.18.0``
  running Python 3 and version ``>= 7.18.0`` are now enforcing UTF8 encoding
  while running checks (and while running pdb debugger with `-b` option on the
  `check` cli command). Previous versions of the Agent were already using this
  encoding by default (depending on the environment variables) without enforcing it.


.. _Release Notes_7.17.2:

7.17.2
======

.. _Release Notes_7.17.2_Prelude:

Prelude
-------

Release on: 2020-02-26

This is a Windows-only release.


.. _Release Notes_7.17.2_Bug Fixes:

Bug Fixes
---------

- On Windows, fixes the Agent 7 installation causing the machine
  to reboot if the C runtime was upgraded when in use.

.. _Release Notes_7.17.1:

7.17.1 / 6.17.1
======

.. _Release Notes_7.17.1_Prelude:

Prelude
-------

Release on: 2020-02-20

- Please refer to the `7.17.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7171>`_ for the list of changes on the Core Checks


.. _Release Notes_7.17.1_Bug Fixes:

Bug Fixes
---------

- Fix a panic in the log agent when the auto-discovery reports new containers to monitor
  and the agent fails to connect to the docker daemon.
  The main setup where this happened is on ECS Fargate where the ECS auto-discovery is watching
  for new containers and the docker socket is not available from the datadog agent.

- Fix DNS resolution for NPM when the system-probe is running in a container on a non-host network.

.. _Release Notes_7.17.0:

7.17.0 / 6.17.0
======

.. _Release Notes_7.17.0_Prelude:

Prelude
-------

Release on: 2020-02-04

- Please refer to the `7.17.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7170>`_ for the list of changes on the Core Checks


.. _Release Notes_7.17.0_Upgrade Notes:

Upgrade Notes
-------------

- Change agents base images to Debian bullseye

- Starting with this version, the containerized Agent never chooses the OS hostname as its hostname when it is running in a dedicated UTS namespace.
  This is done in order to avoid picking container IDs or kubernetes POD names as hostnames, since these identifiers do not reflect the identity of the host they run on.

  This change only affects you if your agent is currently using a container ID or a kubernetes POD name as hostname.
  The hostname of the agent can be checked with ``agent hostname``.
  If the output stays stable when the container or POD of the agent is destroyed and recreated, you’re not impacted by this change.
  If the output changes, it means that the agent was unable to talk to EC2/GKE metadata server, it was unable to get the k8s node name from the kubelet, it was unable to get the hostname from the docker daemon and it is running in its dedicated UTS namespace.
  Under those conditions, you should set explicitly define the host name to be used by the agent in its configuration file.


.. _Release Notes_7.17.0_New Features:

New Features
------------

- Add logic to support querying the kubelet through the APIServer to monitor AWS Fargate on Amazon EKS.

- Add mapping feature to dogstatsd to convert parts of dogstatsd/statsd
  metric names to tags using mapping rules in dogstatsd using wildcard and
  regex patterns.

- Resource tag collection on ECS.

- Add container_mode in journald input to set source/service as Docker image short name when we receive container logs


.. _Release Notes_7.17.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add kube_node_role tag in host metadata for the node role based on the ``kubernetes.io/role`` label.

- Add cluster_name tag in host metadata tags. Cluster name used is read from
  config if set by user or autodiscovered from cloud provider or Kubernetes
  node label.

- The Agent check command displays the distribution metrics.
  The Agent status command displays histogram bucket samples.

- The system-probe will augment network connection information with
  DNS names gathered by inspecting local DNS traffic.

- Users can now use references to capture groups
  in mask sequence replacement_placeholder strings

- Do not apply the metric namespace configured under ``statsd_metric_namespace`` to dogstatsd metrics prefixed with ``datadog.tracer``. Tracer metrics are published with this prefix.


.. _Release Notes_7.17.0_Bug Fixes:

Bug Fixes
---------

- APM: The trace-agent now correctly applies ``log_to_console``, ``log_to_syslog``
  and all other syslog settings.

- Make the log agent continuously retry to connect to docker rather than giving up when docker is not running when the agent is started.
  This is to handle the case where the agent is started while the docker daemon is stopped and the docker daemon is started later while the datadog agent is already running.

- Fixes #4650 [v7] Syntax in /readsecret.py for Py3

- Fixes an issue in Docker where mounting empty directories to disable docker check results in an error.

- Fixes the matching of container id in Tagger (due to runtime prefix) by matching on the 'id' part only

- Fix the node roles to host tags feature by handling the other official Kube way to setting node roles (when multiple roles are required)

- Properly check for "true" value of env var DD_LEADER_ELECTION

- It's possible now to reduce the risk of missing kubernetes tags on initial logs by configuring "logs_config.tagger_warmup_duration".
  Configuring "logs_config.tagger_warmup_duration" delays the send of the first logs of a container.
  Default value 0 seconds, the fix is disabled by default.
  Setting "logs_config.tagger_warmup_duration" to 5 (seconds) should be enough to retrieve all the tags.

- Fix eBPF code compilation errors about ``asm goto`` on Ubuntu 19.04 (Disco)

- Fix race condition in singleton initialization

- On Windows, fixes registration of agent as event log source.  Allows
  agent to correctly write to the Windows event log.

- On Windows, when upgrading, installer will fail if the user attempts
  to assign a configuration file directory or binary directory that is
  different from the original.

- Add logic to support docker restart of containers.

- Fix a Network Performance Monitoring issue where TCP connection direction was incorrectly classified as ``outgoing`` in containerized environments.

- Fixed a few edge cases that could lead to events payloads being rejected by Datadog's intake for being too big.


.. _Release Notes_7.17.0_Other Notes:

Other Notes
-----------

- Upgrade embedded dependencies: ``curl`` to ``7.66.0``, ``autoconf`` to ``2.69``,
  ``procps`` to ``3.3.16``

- JMXFetch upgraded to `0.34.0 <https://github.com/DataDog/jmxfetch/releases/0.34.0>`_

- Bump embedded Python 3 to 3.7.6


.. _Release Notes_7.16.1:

7.16.1 / 6.16.1
========

.. _Release Notes_7.16.1_Prelude:

Prelude
-------

Release on: 2020-01-06

- Please refer to the `7.16.1 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7161>`_ for the list of changes on the Core Checks


.. _Release Notes_7.16.1_Security Issues:

Security Issues
---------------

- UnixODBC software dependency bumped to 2.3.7 to address `CVE-2018-7409
  <https://access.redhat.com/security/cve/cve-2018-7409>`_.


.. _Release Notes_7.16.0:

7.16.0 / 6.16.0
======

.. _Release Notes_7.16.0_Prelude:

Prelude
-------

Release on: 2019-12-18

This release introduces major version 7 of the Datadog Agent, which starts at v7.16.0. The only change from Agent v6 is that
v7 defaults to Python 3 and only includes support for Python 3. Before upgrading to v7, confirm that any
custom checks you have are compatible with Python 3. See this `guide <https://docs.datadoghq.com/agent/guide/python-3/>`_
for more information.

Except for the supported Python versions, v7.16.0 and v6.16.0 have the same features.

Please refer to the `7.16.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-7160>`_ for the list of changes on the Core Checks


.. _Release Notes_7.16.0_New Features:

New Features
------------

- Add support for SysVInit on SUSE 11.

- Add information on endpoints inside the logs-agent section of the agent status.


.. _Release Notes_7.16.0_Enhancement Notes:

Enhancement Notes
-----------------

- Add Python 3 linter results to status page

- Log a warning when the hostname defined in the configuration will not be used as the in-app hostname.

- Add ``ignore_autodiscovery_tags`` parameter config check.

  In some cases, a check should not receive tags coming from the autodiscovery listeners.
  By default ``ignore_autodiscovery_tags`` is set to false which doesn't change the behavior of the checks.
  The first check that will use it is ``kubernetes_state``.

- Adds a new ``flare_stripped_keys`` config setting to clean up additional
  configuration information from flare.

- Adding a new config option ``exclude_gce_tags``, to configure which metadata
  attribute from Google Cloud Engine to exclude from being converted into
  host tags.

- Extends the docker and containerd checks to include an open file descriptors
  metric. This metric reports the number of open file descriptors per container.

- Allow the Agent to schedule different checks from different sources on the same service.


.. _Release Notes_7.16.0_Bug Fixes:

Bug Fixes
---------

- APM: Added a fallback into the SQL obfuscator to handle SQL engines that treat
  backslashes literally.

- The default list of sensitive keywords for process argument scrubbing now uses wildcards before and after.

- On Windows process agent, fix problem wherein if the agent is unable
  to figure out the process user name, the process info/stats were not
  sent at all.  Now sends all relevant stats without the username

- On windows, correctly deletes python 3 precompiled files (.pyc) in
  the event of an installation failure and rollback

- Logs: tailed files discovered through a configuration entry with
  wildcard will properly have the ``dirname`` tag on all log entries.

- Fix small memory leak in ``datadog_agent.set_external_tags`` when an empty
  source_type dict is passed for a given hostname.

- Carry a custom patch for jaydebeapi to support latest jpype.

- Check that cluster-name provided by configuraiton file are compliant with the same rule as on GKE. Logs an error and ignore it otherwise.


.. _Release Notes_7.16.0_Other Notes:

Other Notes
-----------

- JMXFetch upgraded to `0.33.1 <https://github.com/DataDog/jmxfetch/releases/0.33.1>`_

- JQuery, used in the web base agent GUI, has been upgraded to 3.4.1


.. _Release Notes_6.15.1:

6.15.1
======

.. _Release Notes_6.15.1_Prelude:

Prelude
-------

Release on: 2019-11-27
This release was published for Windows on 2019-12-09.

.. _Release Notes_6.15.1_New Features:

New Features
------------

- Collect IP address from containers in awsvpc mode

.. _Release Notes_6.15.1_Bug Fixes:

Bug Fixes
---------

- Reintroduce legacy checks directory to make legacy AgentCheck import path
  (``from checks import AgentCheck``) work again.

- Systemd integration points are re-ordered so that ``dbus`` is used in
  preference to the systemd private API at ``/run/systemd/private``, as per
  the systemd documentation. This prevents unnecessary logging to the system
  journal when datadog-agent is run without root permissions.


.. _Release Notes_6.15.1_Other Notes:

Other Notes
-----------

- Bump embedded Python to 2.7.17.

.. _Release Notes_6.15.0:


6.15.0
======

.. _Release Notes_6.15.0_Prelude:

Prelude
-------

Release on: 2019-11-05

- Please refer to the `6.15.0 tag on integrations-core <https://github.com/DataDog/integrations-core/blob/master/AGENT_CHANGELOG.md#datadog-agent-version-6150>`_ for the list of changes on the Core Checks


.. _Release Notes_6.15.0_New Features:

New Features
------------

- Add persistent volume claim as tag (``persistentvolumeclaim:<pvc_name>``) to StatefulSets pods.

- APM: On SQL obfuscation errors, a detailed explanation is presented when DEBUG logging
  level is enabled.

- APM: SQL obfuscation now supports queries with UTF-8 characters.

- Augment network data with DNS information.

- Add an option to disable the cluster agent local fallback for tag collection (disabled by default).

- DNS lookup information is now included with network data via system-probe.

- Add support for the `XX:+UseContainerSupport` JVM option through the
  `jmx_use_container_support` configuration option.

- The Cluster Agent can now collect stats from Cluster Level Check runners
  to optimize its dispatching logic and rebalance the scheduled checks.

- Add a new python API to store and retrieve data.
  `datadog_agent.write_persistent_cache(key, value)` persists the data in
  `value` (as a string), whereas `datadog_agent.read_persistent_cache(key)`
  returns it for usage afterwards.

- Adding support for compression when forwarding logs through HTTPS. Enable it
  by following instructions
  `here <https://docs.datadoghq.com/agent/logs/?tab=httpcompressed#send-logs-over-https>`_

.. _Release Notes_6.15.0_Enhancement Notes:
