@echo off
:: Rwased EDR active-response shim: forwards the wazuh-execd stdin JSON to the
:: PowerShell script of the same name. Windows AR commands must be a single
:: executable in active-response\bin; .cmd wrappers are the established pattern
:: (see route-null.cmd / restart-ossec.cmd).
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0edr-quarantine-file.ps1"
