# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import pytest

from qa_adapter_kit import AdapterFault
from qa_selenium import Locator, parse_locator


@pytest.mark.parametrize("text,css", [("css=div.a > b", "div.a > b"), ("id=title", '[id="title"]'), ("name=user", '[name="user"]'),
                                      ("testid=submit-btn", '[data-testid="submit-btn"]')])
def test_valid_locators(text, css):
    loc = parse_locator(text)
    assert loc.css() == css and str(loc) == text


@pytest.mark.parametrize("text", ["", "title", "xpath=//a", "id=", "id= ", "id=a b", 'id=a"]', "name=a;b", "testid=a\nb", "css=a{b}", "css=a;b",
                                  "css=a\\b", "css=" + "x" * 600, "id=a\x00b", None, 5])
def test_invalid_locators_are_refused(text):
    with pytest.raises(AdapterFault):
        parse_locator(text)


def test_an_id_value_cannot_break_out_of_the_attribute_selector():
    for evil in ('a"] , body , ["x', "a'b", "a]b"):
        with pytest.raises(AdapterFault):
            parse_locator(f"id={evil}")
