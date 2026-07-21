// Slim, unintrusive "your activity is being recorded" bar for ephemeral
// System Manager sessions. Gated on boot.access_guard_ephemeral (set from
// the grant file by access_guard.boot.boot_session), never a DB flag.
// Deliberately avoids touching desk DOM internals — a single fixed banner,
// no page/layout hooks.
frappe.provide("access_guard");

$(document).ready(function () {
	try {
		var boot = frappe.boot || {};
		if (!boot.access_guard_ephemeral) {
			return;
		}
		var text =
			boot.access_guard_notice_text ||
			"Your activity on this site is being recorded for audit.";

		var bar = $(
			'<div id="access-guard-monitoring-bar" style="' +
				"position:fixed;bottom:0;left:0;right:0;z-index:100000;" +
				"background:#78716c;color:#fff;text-align:center;" +
				"font-size:11px;padding:3px 8px;font-family:inherit;" +
				"opacity:0.85;" +
				'">' +
				frappe.utils.escape_html(text) +
				"</div>"
		);
		$("body").append(bar);
		// Reserve real space for the bar (measured, not guessed) so it
		// supplements the page instead of covering whatever's underneath.
		$("body").css("padding-bottom", bar.outerHeight() + "px");
	} catch (e) {
		// Never let the notice bar break the desk.
		console.error("access_guard monitoring notice failed", e); // eslint-disable-line no-console
	}
});
