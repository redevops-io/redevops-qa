*** Settings ***
Documentation     The order discount rule of the fixture app, checked through its JSON API. The suite RECORDS what it saw as qa-observe tags; the independent
...               verifier compares the record with the value frozen in the plan. The Should Be Equal lines below are this engine's own check (its native result),
...               which the report keeps apart from the verdict.
Library           OrderApi.py

*** Test Cases ***
Order Discount Rule
    [Documentation]    10 percent of the subtotal, rounded down to the cent, from a subtotal of 10000 cents; integer cents only.
    ${t101}=    Get Order Total Cents    101
    ${t102}=    Get Order Total Cents    102
    ${t103}=    Get Order Total Cents    103
    ${t104}=    Get Order Total Cents    104
    Set Tags    qa-observe:order_101_total_cents=${t101}
    Set Tags    qa-observe:order_102_total_cents=${t102}
    Set Tags    qa-observe:order_103_total_cents=${t103}
    Set Tags    qa-observe:order_104_total_cents=${t104}
    Should Be Equal As Integers    ${t101}    9450
    Should Be Equal As Integers    ${t102}    9999
    Should Be Equal As Integers    ${t103}    9000
    Should Be Equal As Integers    ${t104}    9005
