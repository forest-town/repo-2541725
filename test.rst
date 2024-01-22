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


