// localStorage (not sessionStorage) so the shown-hash persists across tabs.
const STORAGE_KEY = "access_guard_notice_shown_hash";
const NOTICE_TEXT = "Your activity on this site is being recorded for audit.";

$(document).on("app_ready", () => {
	const boot = frappe.boot || {};
	if (!boot.access_guard_ephemeral) {
		return;
	}
	const hash = boot.access_guard_login_hash;
	if (localStorage.getItem(STORAGE_KEY) === hash) {
		return;
	}
	frappe.msgprint({ message: frappe.utils.escape_html(NOTICE_TEXT), title: __("Notice") });
	localStorage.setItem(STORAGE_KEY, hash);
});
