app_name = "access_guard"
app_title = "Access Guard"
app_publisher = "Aakvatech Limited"
app_description = "Client-side enforcement and logging for ephemeral Frappe site access"
app_email = "info@aakvatech.com"
app_license = "mit"

require_type_annotated_api_methods = True

app_include_js = "/assets/access_guard/js/monitoring_notice.js"

# boot_session: stamp bootinfo with an "am I ephemeral?" flag derived from
# the grant file (never a DB flag).
boot_session = "access_guard.boot.boot_session"

# on_logout: immediate teardown of an ephemeral session so it doesn't
# linger until the next reaper tick; records the logout reason.
on_logout = "access_guard.reaper.teardown_on_logout"

doc_events = {
	"*": {
		"validate": [
			"access_guard.session_guard.validate",
		],
		"before_submit": "access_guard.session_guard.before_submit",
		"before_cancel": "access_guard.session_guard.before_cancel",
		"on_trash": [
			"access_guard.session_guard.on_trash",
			"access_guard.always_log.on_trash",
		],
		"on_update": "access_guard.always_log.on_update",
	}
}

scheduler_events = {
	"cron": {
		# ~15 min reaper, per BUILD_PLAN.md task 4.
		"*/15 * * * *": [
			"access_guard.reaper.reap_idle_sessions",
		],
	},
	"hourly": [
		"access_guard.sync.sync_hourly",
	],
}

before_request = ["access_guard.request_hooks.before_request"]
after_request = ["access_guard.request_hooks.after_request"]
