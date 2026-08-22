"""Run the real local service and check its public and admin layouts in Chromium."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from playwright.sync_api import Browser, Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
VIEWPORTS = (320, 390, 768, 1024, 1440)

pytestmark = pytest.mark.release


def capture_visual(page: Page, name: str) -> None:
    if os.getenv("ODR_CAPTURE_VISUALS") != "1":
        return
    destination = ROOT / "screenshots" / "release-rehearsal"
    destination.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=destination / f"{name}.png", full_page=True)


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_ready(origin: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"preview exited before readiness ({process.returncode}):\n{output}")
        try:
            with urlopen(f"{origin}/health/ready", timeout=1) as response:  # noqa: S310 - fixed loopback URL
                if response.status == 200:
                    return
        except (OSError, URLError):
            time.sleep(0.15)
    raise TimeoutError("preview did not become ready")


def assert_no_overflow(page: Page, label: str) -> None:
    dimensions = page.evaluate(
        """() => ({
          viewport: window.innerWidth,
          client: document.documentElement.clientWidth,
          document: document.documentElement.scrollWidth,
          body: document.body.scrollWidth,
          offenders: [...document.querySelectorAll('body *')]
            .map(element => ({
              name: element.tagName.toLowerCase(),
              className: typeof element.className === 'string' ? element.className : '',
              left: Math.round(element.getBoundingClientRect().left),
              right: Math.round(element.getBoundingClientRect().right),
            }))
            .filter(element => element.left < -1 || element.right > window.innerWidth + 1)
            .slice(0, 8),
        })"""
    )
    maximum = max(int(dimensions["document"]), int(dimensions["body"]))
    assert maximum <= int(dimensions["viewport"]) + 1, f"horizontal overflow on {label}: {dimensions}"


def assert_named_controls(page: Page, label: str) -> None:
    unnamed = page.locator("button, input, select, textarea").evaluate_all(
        """elements => elements.filter(element => {
          if (element.hidden || element.closest('[hidden]') || element.type === 'hidden') return false;
          const labelled = element.getAttribute('aria-label') || element.getAttribute('aria-labelledby');
          const label = element.id && document.querySelector(`label[for="${CSS.escape(element.id)}"]`);
          return !labelled && !label && element.tagName !== 'BUTTON' && !element.closest('label');
        }).map(element => element.id || element.name || element.outerHTML.slice(0, 80))"""
    )
    assert unnamed == [], f"unnamed controls on {label}: {unnamed}"


def assert_visible_focus(page: Page, label: str) -> None:
    focus = page.evaluate(
        """() => {
          const element = document.activeElement;
          const style = getComputedStyle(element);
          return {
            element: element.id || element.className || element.tagName,
            outlineStyle: style.outlineStyle,
            outlineWidth: style.outlineWidth,
          };
        }"""
    )
    assert focus["outlineStyle"] != "none" and focus["outlineWidth"] != "0px", f"invisible focus on {label}: {focus}"


def audit_public(browser: Browser, origin: str) -> int:
    assertions = 0
    for width in VIEWPORTS:
        context = browser.new_context(viewport={"width": width, "height": 900}, reduced_motion="reduce")
        page = context.new_page()
        console_errors: list[str] = []
        page.on(
            "console",
            lambda message, errors=console_errors: errors.append(message.text) if message.type == "error" else None,
        )
        response = page.goto(origin, wait_until="networkidle")
        assert response is not None and response.status == 200
        page.get_by_role("heading", name="Potential impersonation domains, surfaced for review.").wait_for()
        assert page.locator("main").count() == 1
        assert page.locator(".signal-table").count() == 1
        assert_no_overflow(page, f"public/{width}")
        assert_named_controls(page, f"public/{width}")
        assert not console_errors, f"console errors on public/{width}: {console_errors}"
        if width in {390, 1440}:
            capture_visual(page, f"public-{width}")
        context.close()
        assertions += 1

    context = browser.new_context(viewport={"width": 390, "height": 900}, java_script_enabled=False)
    page = context.new_page()
    response = page.goto(origin, wait_until="domcontentloaded")
    assert response is not None and response.status == 200
    assert page.get_by_text("A listing is a lead, not proof of malicious intent.", exact=False).is_visible()
    assert_no_overflow(page, "public/no-js")
    context.close()
    return assertions + 1


def audit_admin(browser: Browser, origin: str, environment: dict[str, str]) -> int:
    context = browser.new_context(viewport={"width": 390, "height": 900}, reduced_motion="reduce")
    page = context.new_page()
    console_errors: list[str] = []
    page.on(
        "console",
        lambda message, errors=console_errors: errors.append(message.text) if message.type == "error" else None,
    )
    response = page.goto(f"{origin}/admin", wait_until="networkidle")
    assert response is not None and response.status == 200
    page.locator("#setup-view").wait_for(state="visible")
    assert page.get_by_text("Create the operator from a trusted terminal", exact=False).is_visible()
    assert_no_overflow(page, "admin/bootstrap")
    assert_named_controls(page, "admin/bootstrap")

    # Account creation must stay on the trusted CLI, even in browser tests.
    subprocess.run(  # noqa: S603 - controlled interpreter/module argv
        [sys.executable, "-m", "open_domain_radar.cli", "create-admin", "--username", "operator", "--password-stdin"],
        cwd=ROOT,
        env=environment,
        input="correct-horse-battery-staple\n",
        check=True,
        capture_output=True,
        text=True,
    )
    page.reload(wait_until="networkidle")
    page.locator("#login-username").fill("operator")
    page.locator("#login-password").fill("correct-horse-battery-staple")
    page.locator("#login-form button[type='submit']").click()
    page.locator("#workspace").wait_for(state="visible")
    page.get_by_role("heading", name="Collection overview").wait_for()
    page.locator("button[data-section='integrations']").click()
    secret_inputs = page.locator("input[type='password'][autocomplete='new-password']")
    secret_inputs.first.wait_for(state="attached")
    assert secret_inputs.count() >= 1
    stored = page.evaluate(
        """() => Object.keys(localStorage)
          .concat(Object.keys(sessionStorage))
          .filter(key => /api.?key|secret|token/i.test(key))"""
    )
    assert stored == [], f"secret-like browser storage keys: {stored}"
    assert_no_overflow(page, "admin/console-mobile")
    assert not console_errors, f"console errors on admin: {console_errors}"
    capture_visual(page, "admin-390")

    desktop = context.new_page()
    desktop.set_viewport_size({"width": 1440, "height": 950})
    response = desktop.goto(f"{origin}/admin", wait_until="domcontentloaded")
    assert response is not None and response.status == 200
    desktop.locator("#workspace").wait_for(state="visible")
    assert_no_overflow(desktop, "admin/console-desktop")
    capture_visual(desktop, "admin-1440")
    context.close()

    context = browser.new_context(viewport={"width": 390, "height": 900}, java_script_enabled=False)
    page = context.new_page()
    response = page.goto(f"{origin}/admin", wait_until="domcontentloaded")
    assert response is not None and response.status == 200
    fallback = page.locator(".noscript")
    assert fallback.count() == 1, page.locator("body").inner_text()
    assert fallback.is_visible(), page.locator("body").inner_text()
    assert "JavaScript is required for the protected operator console" in fallback.inner_text()
    assert_no_overflow(page, "admin/no-js")
    context.close()
    return 3


def audit_accessibility_modes(browser: Browser, origin: str) -> int:
    context = browser.new_context(viewport={"width": 390, "height": 900}, forced_colors="active")
    page = context.new_page()
    response = page.goto(origin, wait_until="networkidle")
    assert response is not None and response.status == 200
    assert page.evaluate("matchMedia('(forced-colors: active)').matches") is True

    page.keyboard.press("Tab")
    assert page.locator(".skip-link").evaluate("element => element === document.activeElement")
    assert page.locator(".skip-link").is_visible()
    assert_visible_focus(page, "forced-colours/skip-link")
    page.keyboard.press("Enter")
    assert page.locator("#main-content").evaluate("element => element === document.activeElement")

    page.locator("#filter-query").focus()
    for expected in ("filter-status", "filter-source", "filter-target"):
        page.keyboard.press("Tab")
        assert page.evaluate("document.activeElement.id") == expected
        assert_visible_focus(page, f"keyboard/{expected}")
    assert_no_overflow(page, "public/forced-colours")
    context.close()

    # At a 320 CSS-pixel viewport the layout exercises the same reflow breakpoints
    # as a 1280-pixel desktop viewport at 400% browser zoom.  A second pass with
    # 200% text catches fixed-height clipping that viewport checks alone miss.
    context = browser.new_context(viewport={"width": 320, "height": 900})
    page = context.new_page()
    response = page.goto(origin, wait_until="networkidle")
    assert response is not None and response.status == 200
    assert_no_overflow(page, "public/400-percent-reflow-equivalent")
    page.evaluate("document.documentElement.style.fontSize = '200%'")
    assert page.get_by_role("heading", name="Potential impersonation domains, surfaced for review.").is_visible()
    assert page.locator("#signal-filters").evaluate("element => element.getBoundingClientRect().height > 0")
    assert_no_overflow(page, "public/200-percent-text")
    context.close()
    return 2


def test_public_and_admin_interfaces_across_supported_viewports() -> None:
    port = free_port()
    origin = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="open-domain-radar-") as data_dir:
        environment = os.environ.copy()
        environment.update(
            {
                "ODR_DATA_DIR": data_dir,
                "ODR_HOST": "127.0.0.1",
                "ODR_PORT": str(port),
                "ODR_PUBLIC_ORIGIN": origin,
                "ODR_EMBED_WORKER": "false",
                "PYTHONUNBUFFERED": "1",
            }
        )
        subprocess.run(
            [sys.executable, "-m", "open_domain_radar.cli", "init"],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        process = subprocess.Popen(  # noqa: S603 - controlled interpreter/module argv
            [sys.executable, "-m", "open_domain_radar.cli", "serve"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            wait_ready(origin, process)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                try:
                    assertions = (
                        audit_public(browser, origin)
                        + audit_admin(browser, origin, environment)
                        + audit_accessibility_modes(browser, origin)
                    )
                finally:
                    browser.close()
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    assert assertions == len(VIEWPORTS) + 6
