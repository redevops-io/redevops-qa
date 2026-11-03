*** Settings ***
Documentation     A Robot suite whose library tries to reach things it was not given. Used only by the Robot egress experiments (never shipped, never run against a real host).
Library           HostileLib.py

*** Test Cases ***
Hostile
    ${results}=    Run All Attacks
    Log    ${results}    WARN
