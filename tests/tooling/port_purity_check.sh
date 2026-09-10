#!/usr/bin/env bash
#
# port_purity_check.sh — keep modules/ compilable from one source on every port.
#
# WHAT IS BEING PREVENTED. modules/ is the shared tree: the same files compile
# under Zephyr, ESP-IDF and the host cc. A platform include or a kernel call
# added to a shared file builds cleanly on the port it was written on and breaks
# the other two at the worst time — after the change looked done. This gate
# fails the commit instead. Three shapes are banned in modules/** sources:
#
#   1. platform includes   Zephyr, ESP-IDF, or canonical FreeRTOS headers
#   2. Zephyr kernel API   k_work*, k_sem*, k_thread*, k_timer*, k_fifo*,
#                          k_msleep, SYS_INIT, K_WORK_*, K_SEM_*, flash_area_*,
#                          sys_reboot — platform code goes through ultrawidelock_port
#   3. crypto provider API PSA, mbedTLS, OpenSSL, or wolfSSL includes and calls;
#                          portable code goes through ultrawidelock_prim.h
#
# and one shape is banned in platform-owned trees, which is the same rule read
# from the other side: each names exactly one OS (check_port_os). modules/ names
# none, and the Zephyr, ESP-IDF, and standalone FreeRTOS trees may name only
# their own platform. A file naming the wrong one is in the wrong tree.
#
#   tests/tooling/port_purity_check.sh              # scan the tracked sources
#   tests/tooling/port_purity_check.sh --self-test  # prove the gate can fail
#   make check / make purity                        # runs it as the `purity` suite
#
# Exit 0 clean, 1 on a finding, 2 if the gate could not do its job.
#
# WHAT IS EXEMPT, permanently, and why each one is not a hole:
#
#   modules/ultrawidelock_port/                the contract itself: its whole job is to be
#                                    the one place platform branches live
#   modules/ultrawidelock_dw3000/dwt_uwb_driver/   vendored Qorvo decadriver
#   modules/ultrawidelock_dfu/src/detools/         vendored delta-patch engine
#   ultrawidelock_cred_stack/{cred_stack,session}.cpp  adapters to the Nordic add-on's
#                                    <aliro/*> API; the add-on's own headers
#                                    include Zephyr, so these can never be pure
#   ultrawidelock_nfc/src/transport_pn532.cpp  same class of adapter: its threading
#                                    contract IS the add-on's workqueue
#                                    (AliroWorkqueueSubmit takes a k_work), and
#                                    it includes aliro/ + reader_storage headers
#   ultrawidelock_nfc/src/nfc_prop_ecp.cpp     same: grafts into the add-on's
#                                    subsys/nfc_prop, add-on headers included
#   ultrawidelock_uwb/include/ultrawidelock_util.h    portable shim that defers to the Zephyr
#                                    header under #ifdef __ZEPHYR__ and carries
#                                    its own fallback otherwise (ultrawidelock_bytes.h,
#                                    its sibling, now lives in ultrawidelock_port)
#
# THE RATCHET. Every other exemption is a file still waiting on its unification
# tranche, listed in RATCHET below with the tranche that retires it. A ratchet
# entry that stops tripping the ban is a FAILURE ("stale") — finishing a
# conversion and shrinking this list are the same commit, so the list can only
# go down. RATCHET is empty: modules/ is one-source and the permanent list
# above is the whole story.
#
# The permanent list is ratcheted the same way, because "permanent" is a claim
# about today's adapters, not a licence. Each named file must still trip the
# ban and each named directory must still exist; an adapter that becomes
# portable, or moves, fails the gate until its line goes too. An exemption
# nobody can retire is an exemption nobody is checking.
#
# TWO MORE PERMANENT CHECKS ride in this gate because no Zephyr/ESP build runs
# on this machine — a path or symbol a build file hardcodes is otherwise proven
# only on hardware CI, after the tree already moved:
#
#   build-file paths   every path literal a CMakeLists or a -DZEPHYR_EXTRA_MODULES
#                      list names must exist in the tree (check_build_paths)
#   patch symbols      every ultrawidelock identifier a integrations/nrfconnect-door-lock/patches/*.patch
#                      grafts into the Nordic add-on must still be defined in
#                      modules/ or ports/ (check_patch_symbols)
#   role manifests     modules/*/roles/*.list is the ONE place a shared source is
#                      assigned to a role; cmake/ultrawidelock_roles.cmake and
#                      tests/host/sources.sh read them instead of carrying their
#                      own copies. check_manifests keeps that true: every listed
#                      path exists, no file sits in two roles (a consumer taking
#                      both would compile it twice), and every shared source
#                      under MANIFEST_ROOTS is in a role or in the
#                      NOT_MANIFESTED allowlist below with its reason.
#   public includes    no propagated CMake include path reaches modules/*/src
#   private headers    production modules, apps and ports never include a
#                      different module's private header; tests may white-box
#                      the implementation they compile
#   HAL contract       ultrawidelock/ultrawidelock_hal.h names exactly the five approved seams
#   crypto boundary    only ultrawidelock_prim_psa.c may reach a raw crypto provider

set -euo pipefail

# Same shape as uwb_seam_check.sh, the sibling gate this one mirrors.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	R=$'\033[31m' G=$'\033[32m' Z=$'\033[0m'
else
	R='' G='' Z=''
fi

cd "$(dirname "$0")/../.."

# One definition each, used by the scan AND the self-test. The include shape is
# written once and specialised per OS, so the modules/ ban and the per-port ban
# can never drift apart on what an include looks like.
INC_RE='^[[:space:]]*#[[:space:]]*include[[:space:]]*["<]'
ZEPHYR_INC_RE="${INC_RE}zephyr/"
ESP_INC_RE="${INC_RE}(freertos/|esp_)"
FREERTOS_INC_RE="${INC_RE}(freertos/)?(FreeRTOS|task|semphr|queue|timers)\.h"
INCLUDE_RE="${INC_RE}(zephyr/|freertos/|esp_|(FreeRTOS|task|semphr|queue|timers)\.h)"
KERNEL_RE='(^|[^_[:alnum:]])(k_(work|sem|thread|timer|fifo|msleep|sleep|usleep|busy_wait|yield)|sys_reboot|flash_area_|SYS_INIT|K_(WORK|SEM|THREAD|TIMER|FIFO|MUTEX)|(x|v|ux|ul)Task[A-Z_][A-Za-z0-9_]*|x(Queue|Semaphore|Timer)[A-Z_][A-Za-z0-9_]*|pvPortMalloc|vPortFree)'
CRYPTO_INCLUDE_RE="${INC_RE}(psa/|mbedtls/|openssl/|wolfssl/)"
CRYPTO_CALL_RE='(^|[^_[:alnum:]])(psa_[A-Za-z0-9_]+|mbedtls_[A-Za-z0-9_]+|EVP_[A-Za-z0-9_]+|wolfSSL_[A-Za-z0-9_]+)[[:space:]]*\('
CRYPTO_PROVIDER=modules/ultrawidelock_cred/src/ultrawidelock_prim_psa.c

# Prose naming a kernel symbol is not a call. Same filter as the seam gate:
# drop comment-opening lines from `grep -n` output, keep code with a trailing
# comment.
COMMENT_LINE_RE='^[0-9]+:[[:space:]]*(\*|//|/\*)'

# The same filter for `grep -nH` output, which prefixes every hit with its path.
# A separate constant rather than a looser shared one: COMMENT_LINE_RE is also
# the seam gate's filter and its self-test's, both of which match against bare
# `line:text`, and widening the anchor for them would let a line whose CODE
# contains a colon and a comment marker pass as prose. Paths in this tree carry
# no colon, so `[^:]*:` is exactly the added prefix and nothing else.
COMMENT_LINE_H_RE='^[^:]*:[0-9]+:[[:space:]]*(\*|//|/\*)'

# Permanent exemptions — see the header for why each is not a hole. Declared as
# plain paths, once, and compiled into the match regex below: the scan skips
# them and the staleness check re-proves each one is still needed, so the list
# cannot outlive its reasons.
PERMANENT_DIRS=(
	modules/ultrawidelock_dw3000/dwt_uwb_driver   # vendored Qorvo decadriver
	modules/ultrawidelock_dfu/src/detools         # vendored delta-patch engine
)
PERMANENT_FILES=(
	# The contract itself: these four headers name every platform on purpose,
	# because selecting the backend is what they are for. Listed one by one
	# rather than exempting modules/ultrawidelock_port wholesale, so that a .c file
	# appearing beside them fails the gate instead of inheriting a blanket
	# pass. Every backend lives in a port tree now (ports/zephyr/osal,
	# ports/esp32/components/ultrawidelock_port, tests/host/port). ultrawidelock_flash.h is
	# deliberately absent: it is pure, and the ratchet says so if that changes.
	modules/ultrawidelock_port/include/ultrawidelock_bytes.h
	modules/ultrawidelock_port/include/ultrawidelock_log.h
	modules/ultrawidelock_port/include/ultrawidelock_osal.h
	modules/ultrawidelock_port/include/ultrawidelock_port.h
	modules/ultrawidelock_cred_stack/src/cred_stack.cpp
	modules/ultrawidelock_cred_stack/src/session.cpp
	modules/ultrawidelock_nfc/src/transport_pn532.cpp
	modules/ultrawidelock_nfc/src/nfc_prop_ecp.cpp
	modules/ultrawidelock_uwb/include/ultrawidelock_util.h
)

permanent_re() { # the two lists as one anchored alternation, dots literal
	local p out=''
	for p in "${PERMANENT_DIRS[@]}"; do out="$out|${p//./\\.}/"; done
	for p in "${PERMANENT_FILES[@]}"; do out="$out|${p//./\\.}"; done
	printf '^(%s)' "${out#|}"
}
PERMANENT_RE=$(permanent_re)

# The ratchet: still-impure files and the tranche that retires each. EMPTY
# since T4: modules/ is one-source and the permanent list above is the whole
# story. Stays declared so a regression has somewhere honest to land — with a
# tranche tag and a reason — and so the ok-line keeps reporting the count.
RATCHET=()

repo_files() { # tracked + untracked files that exist in this working tree
	local f
	git ls-files --cached --others --exclude-standard -- "$@" |
		while IFS= read -r f; do
			[ ! -f "$f" ] || printf '%s\n' "$f"
		done | LC_ALL=C sort -u
}

scan_paths() {
	repo_files 'modules/*.c' 'modules/*.h' 'modules/*.cpp' 'modules/*.hpp'
}

crypto_scan_paths() {
	local f
	while IFS= read -r f; do
		case "$f" in
		modules/ultrawidelock_dw3000/dwt_uwb_driver/* | \
			modules/ultrawidelock_dfu/src/detools/*) continue ;;
		esac
		printf '%s\n' "$f"
	done < <(scan_paths)
}

crypto_file_hits() {
	{
		grep -nE "$CRYPTO_INCLUDE_RE" "$1" || true
		grep -nE "$CRYPTO_CALL_RE" "$1" | grep -vE "$COMMENT_LINE_RE" || true
	} | sort -t: -k1,1n -u
}

crypto_path_allowed() {
	[ "$1" = "$CRYPTO_PROVIDER" ]
}

in_ratchet() {
	# ${arr[@]+...}: bash 3.2 + set -u treats an empty array expansion as unbound.
	local f needle="$1"
	for f in ${RATCHET[@]+"${RATCHET[@]}"}; do
		[ "$f" = "$needle" ] && return 0
	done
	return 1
}

# Banned hits in one file, comment lines dropped, line numbers kept.
file_hits() {
	{
		grep -nE "$INCLUDE_RE" "$1" || true
		grep -nE "$KERNEL_RE" "$1" | grep -vE "$COMMENT_LINE_RE" || true
	} | sort -t: -k1,1n -u
}

# ---- scan -------------------------------------------------------------------

scan() {
	local findings=0 stale=0 f hits

	# The exemptions are applied first and the survivors are grepped in ONE
	# pass, rather than three processes per file across all of modules/. The
	# reported order is unchanged: repo_files already hands these back in
	# LC_ALL=C order, so sorting the combined hits by path and then numerically
	# by line reproduces file-by-file, line-by-line exactly as the per-file
	# `sort -t: -k1,1n -u` did.
	local scan_files=()
	while IFS= read -r f; do
		[[ $f =~ $PERMANENT_RE ]] && continue
		if in_ratchet "$f"; then
			continue
		fi
		scan_files+=("$f")
	done < <(scan_paths)

	if [ ${#scan_files[@]} -gt 0 ]; then
		while IFS= read -r hit; do
			[ -n "$hit" ] || continue
			printf '%s  %s%s\n' "$R" "$hit" "$Z"
			findings=$((findings + 1))
		done < <(
			{
				grep -nHE "$INCLUDE_RE" "${scan_files[@]}" || true
				grep -nHE "$KERNEL_RE" "${scan_files[@]}" |
					grep -vE "$COMMENT_LINE_H_RE" || true
			} | LC_ALL=C sort -t: -k1,1 -k2,2n -u
		)
	fi

	# A ratchet entry that no longer trips the ban is finished work that forgot
	# to shrink the list — or a moved file leaving a hole. Either way: fail.
	for f in ${RATCHET[@]+"${RATCHET[@]}"}; do
		if [ ! -f "$f" ] || [ -z "$(file_hits "$f")" ]; then
			printf '%s  stale ratchet entry: %s%s\n' "$R" "$f" "$Z" >&2
			stale=$((stale + 1))
		fi
	done

	# Same discipline for the permanent list, which no tranche will ever empty:
	# an adapter that became pure, or moved, must lose its exemption in that
	# commit. Otherwise the entry keeps covering a path nobody is watching.
	for f in "${PERMANENT_FILES[@]}"; do
		if [ ! -f "$f" ]; then
			printf '%s  stale permanent exemption: %s (gone)%s\n' "$R" "$f" "$Z" >&2
			stale=$((stale + 1))
		elif [ -z "$(file_hits "$f")" ]; then
			printf '%s  stale permanent exemption: %s (now pure — drop it)%s\n' \
				"$R" "$f" "$Z" >&2
			stale=$((stale + 1))
		fi
	done
	for f in "${PERMANENT_DIRS[@]}"; do
		if [ ! -d "$f" ]; then
			printf '%s  stale permanent exemption: %s/ (gone)%s\n' "$R" "$f" "$Z" >&2
			stale=$((stale + 1))
		fi
	done

	if [ "$findings" -gt 0 ] || [ "$stale" -gt 0 ]; then
		if [ "$findings" -gt 0 ]; then
			printf '%scheck-purity: %d platform reference(s) in shared modules/%s\n' \
				"$R" "$findings" "$Z" >&2
			printf '  Go through ultrawidelock_port (ultrawidelock_port.h / ultrawidelock_log.h), or move the file\n' >&2
			printf '  to a port tree. RATCHET additions need a tranche tag and a reason.\n' >&2
		fi
		[ "$stale" -eq 0 ] || printf '%scheck-purity: %d stale exemption(s) — an allowlist entry outlived its reason%s\n' \
			"$R" "$stale" "$Z" >&2
		return 1
	fi
	printf '%s  ok   modules/ is platform-pure outside ultrawidelock_port and the exempt adapters%s\n' "$G" "$Z"
	printf '%s  ok   exemptions: %d permanent (%d dir, %d file), %d ratchet, none stale%s\n' \
		"$G" "$((${#PERMANENT_DIRS[@]} + ${#PERMANENT_FILES[@]}))" \
		"${#PERMANENT_DIRS[@]}" "${#PERMANENT_FILES[@]}" "${#RATCHET[@]}" "$Z"
	return 0
}

# ---- portable crypto reaches one provider ----------------------------------

check_crypto_boundary() {
	local fails=0 n=0 provider_hits=0 f hits hit

	while IFS= read -r f; do
		n=$((n + 1))
		hits=$(crypto_file_hits "$f")
		[ -n "$hits" ] || continue
		if crypto_path_allowed "$f"; then
			provider_hits=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
			continue
		fi
		while IFS= read -r hit; do
			[ -n "$hit" ] || continue
			printf '%s  raw crypto provider reference: %s:%s%s\n' \
				"$R" "$f" "$hit" "$Z" >&2
			fails=$((fails + 1))
		done <<<"$hits"
	done < <(crypto_scan_paths)

	selector_live "crypto-boundary module sources" "$n" || return 1
	if [ ! -f "$CRYPTO_PROVIDER" ] || [ "$provider_hits" -eq 0 ]; then
		printf '%s  crypto provider exception is stale: %s%s\n' \
			"$R" "$CRYPTO_PROVIDER" "$Z" >&2
		fails=$((fails + 1))
	fi
	if [ "$fails" -gt 0 ]; then
		printf '%scheck-purity: %d raw crypto provider reference(s) outside ultrawidelock_prim_psa.c%s\n' \
			"$R" "$fails" "$Z" >&2
		return 1
	fi
	printf '%s  ok   crypto boundary: %d module source(s), raw provider API confined to ultrawidelock_prim_psa.c%s\n' \
		"$G" "$n" "$Z"
}

# ---- platform trees keep to their own OS -------------------------------------
#
# The other half of the one-source rule, and the half only reachable now that
# every port has a home: modules/ names no OS, and a port tree names exactly
# one. A Zephyr call in ports/esp32 (or an esp_/FreeRTOS call in ports/zephyr,
# apps/dwm3001cdk-lock/ or examples/zephyr/) is a file that landed in the wrong tree
# — it either belongs in the sibling port, or it is shared code that should sit
# in modules/ behind ultrawidelock_port. Both readings mean the tree, not the file, is
# wrong, and neither is caught by the modules/ scan above.
#
# tests/ is deliberately absent: the host suites include fake <zephyr/*>
# headers on purpose, and their honesty is enforced by compiling, not by this.
ZEPHYR_TREES=(apps/dwm3001cdk-lock apps/nrf5340dk-lock examples/zephyr ports/zephyr)
ESP_TREES=(apps/esp32-matter-lock examples/esp32 ports/esp32)
FREERTOS_TREES=(apps/dwm3001cdk-lock-freertos ports/freertos-nrf52833)

tree_sources() { # <dir>... -> the tracked C/C++ sources under them
	local d args=()
	for d in "$@"; do
		args+=("$d/*.c" "$d/*.h" "$d/*.cpp" "$d/*.hpp")
	done
	repo_files "${args[@]}"
}

os_findings() { # <banned-re> <dir>... -> file:line:text per offence
	# One grep over every file, not a grep and a sed per file. grep already
	# prints `file:line:text` when it is handed more than one path, which is
	# exactly what the per-file sed was reconstructing -- and -H asks for that
	# prefix unconditionally, so a tree that happens to hold a single source
	# formats the same as one that holds forty. Same output, two processes
	# instead of two per file; on this tree that is most of the gate's system
	# time, which was larger than the time it spent matching.
	local re="$1" f
	local files=()
	shift
	while IFS= read -r f; do files+=("$f"); done < <(tree_sources "$@")
	[ ${#files[@]} -eq 0 ] && return 0
	grep -nHE "$re" "${files[@]}" || true
}

check_port_os() {
	local fails=0 n line
	n=$(tree_sources "${ZEPHYR_TREES[@]}" "${ESP_TREES[@]}" "${FREERTOS_TREES[@]}" |
		wc -l | tr -d ' ')

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		printf '%s  esp/freertos include in a Zephyr tree: %s%s\n' "$R" "$line" "$Z" >&2
		fails=$((fails + 1))
	done < <(os_findings "$ESP_INC_RE|$FREERTOS_INC_RE" "${ZEPHYR_TREES[@]}")

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		printf '%s  zephyr include in the ESP-IDF tree: %s%s\n' "$R" "$line" "$Z" >&2
		fails=$((fails + 1))
	done < <(os_findings "$ZEPHYR_INC_RE" "${ESP_TREES[@]}")

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		printf '%s  zephyr include in the standalone FreeRTOS tree: %s%s\n' \
			"$R" "$line" "$Z" >&2
		fails=$((fails + 1))
	done < <(os_findings "$ZEPHYR_INC_RE" "${FREERTOS_TREES[@]}")

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		printf '%s  ESP-IDF include in the standalone FreeRTOS tree: %s%s\n' \
			"$R" "$line" "$Z" >&2
		fails=$((fails + 1))
	done < <(os_findings "$ESP_INC_RE" "${FREERTOS_TREES[@]}")

	if [ "$fails" -gt 0 ]; then
		printf '%scheck-purity: %d cross-OS include(s) in a platform tree%s\n' "$R" "$fails" "$Z" >&2
		printf '  Move the file to the port whose OS it names, or into modules/\n' >&2
		printf '  behind ultrawidelock_port if both ports need it.\n' >&2
		return 1
	fi
	selector_live "platform tree sources" "$n" || return 1
	printf '%s  ok   platform trees: %d source(s), each naming only its own OS%s\n' "$G" "$n" "$Z"
}

# ---- build-file path literals -----------------------------------------------
#
# Resolved path candidates of one CMake file, one per line. Variables expand
# from the file's own single-line set() lines plus REPO_ROOT and
# CMAKE_CURRENT_{SOURCE,LIST}_DIR; a word still carrying ${...} or $ENV{...}
# after that is outside this gate's reach and is skipped, as are comments and
# if(EXISTS ...) probes (existence there is the condition, not a promise).
# Two shapes survive: anything a resolved variable anchored ("./..."), and a
# bare relative file with a source-ish extension (src/main.c, platform/x.c).
cmake_path_list() {
	local d
	d=$(dirname "$1")
	case $d in /*) ;; *) d="./$d" ;; esac
	awk -v dir="$d" '
	function expand(s,  k, hit) {
		gsub(/\$\{REPO_ROOT\}/, ".", s)
		gsub(/\$\{CMAKE_CURRENT_SOURCE_DIR\}/, dir, s)
		gsub(/\$\{CMAKE_CURRENT_LIST_DIR\}/, dir, s)
		do {
			hit = 0
			for (k in v)
				if (index(s, "${" k "}")) { gsub("\\$\\{" k "\\}", v[k], s); hit = 1 }
		} while (hit)
		return s
	}
	{
		sub(/#.*/, "")
		if ($0 ~ /EXISTS/) next
		# message() strings are prose for humans, not path promises; skip the
		# whole call, tracking parens so multi-line FATAL_ERROR blocks vanish.
		if (inmsg) {
			inmsg += gsub(/\(/, "(") - gsub(/\)/, ")")
			if (inmsg < 0) inmsg = 0
			next
		}
		if (match($0, /message[ \t]*\(/)) {
			rest = substr($0, RSTART)
			inmsg = gsub(/\(/, "(", rest) - gsub(/\)/, ")", rest)
			if (inmsg < 0) inmsg = 0
			$0 = substr($0, 1, RSTART - 1)
		}
		if (match($0, /set\([A-Za-z_][A-Za-z0-9_]*[ \t]+[^)]+\)/)) {
			s = substr($0, RSTART + 4, RLENGTH - 5)
			name = s; sub(/[ \t].*/, "", name)
			val = s; sub(/^[^ \t]+[ \t]+/, "", val); gsub(/"/, "", val)
			v[name] = expand(val)
		}
		n = split($0, w, /[ \t()"]+/)
		for (i = 1; i <= n; i++) {
			p = expand(w[i])
			if (p ~ /[{}]/ || p !~ /\//) continue
			if (p ~ /^(\.\/|\/)/) { print p; continue }
			if (p ~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*(\/[A-Za-z0-9_.-]+)+\.(c|cc|cpp|h|hpp|conf|overlay|yml|cmake)$/)
				print dir "/" p
		}
	}' "$1"
}

# Propagated include directories from one CMake file. Only the public forms are
# emitted: Zephyr's global helper, PUBLIC/INTERFACE target scopes, and ESP-IDF
# INCLUDE_DIRS before PRIV_INCLUDE_DIRS. Variables resolve like cmake_path_list.
cmake_public_include_list() {
	local d
	d=$(dirname "$1")
	case $d in /*) ;; *) d="./$d" ;; esac
	awk -v dir="$d" '
	function expand(s,  k, hit) {
		gsub(/\$\{REPO_ROOT\}/, ".", s)
		gsub(/\$\{CMAKE_CURRENT_SOURCE_DIR\}/, dir, s)
		gsub(/\$\{CMAKE_CURRENT_LIST_DIR\}/, dir, s)
		do {
			hit = 0
			for (k in v)
				if (index(s, "${" k "}")) { gsub("\\$\\{" k "\\}", v[k], s); hit = 1 }
		} while (hit)
		return s
	}
	function emit(s, p) {
		p = expand(s)
		if (p == "" || p ~ /[{}]/) return
		if (p !~ /^(\.\/|\/)/) p = dir "/" p
		print p
	}
	{
		line = $0
		sub(/#.*/, "", line)
		if (cmd == "" && match(line, /set\([A-Za-z_][A-Za-z0-9_]*[ \t]+[^)]+\)/)) {
			s = substr(line, RSTART + 4, RLENGTH - 5)
			name = s; sub(/[ \t].*/, "", name)
			val = s; sub(/^[^ \t]+[ \t]+/, "", val); gsub(/"/, "", val)
			v[name] = expand(val)
		}
		paren = line
		opens = gsub(/\(/, "(", paren)
		closes = gsub(/\)/, ")", paren)
		n = split(line, w, /[ \t()"]+/)
		for (i = 1; i <= n; i++) {
			t = w[i]
			if (t == "") continue
			if (cmd == "") {
				if (t == "zephyr_include_directories") { cmd = "zephyr"; pub = 1; continue }
				if (t == "target_include_directories") { cmd = "target"; pub = 0; continue }
				if (t == "idf_component_register") { cmd = "idf"; pub = 0; continue }
				continue
			}
			if (cmd == "target") {
				if (t == "PUBLIC" || t == "INTERFACE") { pub = 1; continue }
				if (t == "PRIVATE") { pub = 0; continue }
				if (t == "SYSTEM" || t == "BEFORE" || t == "AFTER") continue
			} else if (cmd == "idf") {
				if (t == "INCLUDE_DIRS") { pub = 1; continue }
				if (t ~ /^(SRCS|SRC_DIRS|EXCLUDE_SRCS|PRIV_INCLUDE_DIRS|REQUIRES|PRIV_REQUIRES|LDFRAGMENTS|EMBED_FILES|EMBED_TXTFILES|WHOLE_ARCHIVE)$/) {
					pub = 0
					continue
				}
			}
			if (pub) emit(t)
		}
		if (cmd != "") {
			depth += opens - closes
			if (depth <= 0) { cmd = ""; pub = 0; depth = 0 }
		}
	}' "$1"
}

cmake_files() {
	repo_files CMakeLists.txt '**/CMakeLists.txt'
}

# Every check below counts what its selector matched and then reports that count
# in its ok line. A plausible number is exactly what stops anyone looking, so a
# count of zero has to be a failure rather than a clean scan: none of these can
# legitimately be zero in this tree, so zero only ever means the selector stopped
# matching. They also share repo_files, which is what makes this worth stating
# five times -- one broken pathspec takes all of them blind in the same commit,
# and every one of them would still say ok.
selector_live() { # label, count -> 1 if the selector matched nothing
	[ "$2" -gt 0 ] && return 0
	printf '%s  %s matched nothing — the selector stopped looking%s\n' "$R" "$1" "$Z" >&2
	return 1
}

check_public_includes() {
	local fails=0 n=0 f p canon repo
	repo=$(pwd -P)
	while IFS= read -r f; do
		while IFS= read -r p; do
			[ -n "$p" ] || continue
			n=$((n + 1))
			canon="$p"
			[ ! -d "$p" ] || canon=$(cd "$p" && pwd -P)
			case "$canon" in
			"$repo"/modules/ultrawidelock_*/src | "$repo"/modules/ultrawidelock_*/src/* | \
				"$repo"/modules/ultrawidelock_*/src | "$repo"/modules/ultrawidelock_*/src/*)
				printf '%s  private include path is public: %s (named by %s)%s\n' \
					"$R" "$p" "$f" "$Z" >&2
				fails=$((fails + 1))
				;;
			esac
		done < <(cmake_public_include_list "$f")
	done < <(cmake_files)
	if [ "$fails" -gt 0 ]; then
		printf '%scheck-purity: %d modules/*/src include path(s) propagate to consumers%s\n' \
			"$R" "$fails" "$Z" >&2
		return 1
	fi
	selector_live "public include paths" "$n" || return 1
	printf '%s  ok   public includes: %d propagated path(s), none enters modules/*/src%s\n' \
		"$G" "$n" "$Z"
}

# Owned private headers only. The vendored trees are dependencies with their
# own layout and do not define this repository's module boundary.
private_headers() {
	repo_files 'modules/ultrawidelock_*/src/*.h' 'modules/ultrawidelock_*/src/**/*.h' \
		'modules/ultrawidelock_*/src/*.h' 'modules/ultrawidelock_*/src/**/*.h' \
		| grep -vE '^modules/ultrawidelock_dfu/src/detools/'
}

# Production C/C++ files. Tests may include private headers to white-box the
# implementation units they compile; app and port code may not.
boundary_sources() {
	repo_files 'modules/*.c' 'modules/*.h' 'modules/*.cpp' 'modules/*.hpp' \
		'apps/*.c' 'apps/*.h' 'apps/*.cpp' 'apps/*.hpp' \
		'examples/*.c' 'examples/*.h' 'examples/*.cpp' 'examples/*.hpp' \
		'ports/*.c' 'ports/*.h' 'ports/*.cpp' 'ports/*.hpp' \
		| grep -vE '^(modules/ultrawidelock_dw3000/dwt_uwb_driver/|modules/ultrawidelock_dfu/src/detools/)'
}

# Print the private header an include crosses into, or print nothing. A module's
# own implementation may use its own src headers. Its public headers may not.
private_header_target() { # <source> <include-token> <private-header>...
	local src="$1" inc="$2" src_owner='' public_header=0 own=0 candidate=''
	local h owner rel matched
	shift 2
	case "$src" in
	modules/ultrawidelock_*/* | modules/ultrawidelock_*/*)
		src_owner=${src#modules/}
		src_owner=${src_owner%%/*}
		case "$src" in modules/"$src_owner"/include/*) public_header=1 ;; esac
		;;
	esac
	for h in "$@"; do
		owner=${h#modules/}
		owner=${owner%%/*}
		rel=${h#modules/$owner/src/}
		matched=0
		case "$inc" in
		*/*)
			case "$inc" in "$rel" | src/"$rel" | */src/"$rel") matched=1 ;; esac
			;;
		*) [ "$inc" != "${h##*/}" ] || matched=1 ;;
		esac
		[ "$matched" -eq 1 ] || continue
		if [ "$owner" = "$src_owner" ] && [ "$public_header" -eq 0 ]; then
			own=1
		else
			[ -n "$candidate" ] || candidate="$h"
		fi
	done
	[ "$own" -eq 0 ] || return 1
	[ -n "$candidate" ] || return 1
	# Published as a global too, so the per-include caller can read the answer
	# without a command substitution; see check_private_headers.
	PHT_TARGET=$candidate
	printf '%s\n' "$candidate"
}

check_private_headers() {
	local private=() sources=() h f hits hit inc target fails=0 n=0
	while IFS= read -r h; do private+=("$h"); done < <(private_headers)
	# Both the file list and each file's hits are collected before the loop that
	# reads them, and neither is a process substitution inside another loop.
	# bash 3.2 — what macOS ships, and what the CI image's /usr/bin/env finds
	# second — holds a process substitution's descriptor until the enclosing
	# loop ends, so one per file across these 387 sources exhausts a stock
	# 256-descriptor limit partway through and the check dies mid-scan.
	while IFS= read -r h; do sources+=("$h"); done < <(boundary_sources)
	# ONE grep over all 387 sources instead of one per source. That is the
	# single most expensive thing this gate did: the matching itself is
	# nothing, and spawning a process per file was the larger half of the
	# gate's runtime and nearly all of its system time. -H makes grep prefix
	# every hit with its path, so each line arrives as `file:line:text` and the
	# loop below reads the filename from the hit rather than from the loop
	# variable it no longer has. The hits stay in grep's argument order, which
	# is boundary_sources' order, so findings are reported exactly as before.
	local hitlines=""
	if [ ${#sources[@]} -gt 0 ]; then
		hitlines=$(grep -nHE "${INC_RE}[^>\"]+[>\"]" "${sources[@]}" || true)
	fi
	if [ -n "$hitlines" ]; then
		local rest
		while IFS= read -r hit; do
			[ -n "$hit" ] || continue
			n=$((n + 1))
			f=${hit%%:*}
			rest=${hit#*:}
			# Shell-native, and called without a command substitution: this
			# runs once per include in the tree, and a subshell per include
			# exhausts the shell's heap on a tree this size (it aborts around
			# 300 files). INC_RE already guaranteed both delimiters.
			inc=${hit#*[<\"]}
			inc=${inc%%[>\"]*}
			PHT_TARGET=''
			private_header_target "$f" "$inc" "${private[@]}" >/dev/null || continue
			target=$PHT_TARGET
			printf '%s  private header include: %s:%s -> %s%s\n' \
				"$R" "$f" "${rest%%:*}" "$target" "$Z" >&2
			fails=$((fails + 1))
		done <<<"$hitlines"
	fi
	if [ "$fails" -gt 0 ]; then
		printf '%scheck-purity: %d production include(s) cross a module private boundary%s\n' \
			"$R" "$fails" "$Z" >&2
		return 1
	fi
	selector_live "production includes" "$n" || return 1
	printf '%s  ok   private headers: %d production include(s) stay within module boundaries%s\n' \
		"$G" "$n" "$Z"
}

# Every -DZEPHYR_EXTRA_MODULES / -DEXTRA_ZEPHYR_MODULES entry the build
# recipes pass, repo-relative. Covers the nRF5340DK lock build and mk/*.mk,
# notably mk/cdk.mk injecting ultrawidelock_dfu at the sysbuild level.
module_list_paths() {
	grep -hoE -- '-D(ZEPHYR_EXTRA_MODULES|EXTRA_ZEPHYR_MODULES)=[^[:space:]]+' \
		scripts/nrf5340dk-build.sh mk/*.mk \
		| sed -e 's/^-D[A-Z_]*=//' -e "s/[\"']//g" \
		| tr ';' '\n' \
		| sed -e 's|^\$TREE|.|' -e 's|^\$(REPO_ROOT)|.|' -e 's|^\${REPO_ROOT}|.|'
}

# The build files whose hardcoded paths this gate resolves.
BUILD_FILES=(
	CMakeLists.txt
	apps/dwm3001cdk-lock/CMakeLists.txt
	apps/esp32-matter-lock/CMakeLists.txt
	apps/satellite/CMakeLists.txt
	examples/zephyr/anchor/CMakeLists.txt
	examples/zephyr/nrf5340dk-initiator/CMakeLists.txt
	examples/esp32/*/CMakeLists.txt
	tests/on_target/zephyr/nrf5340dk-ultrawidelock-device-ec/CMakeLists.txt
	ports/zephyr/CMakeLists.txt
	modules/*/CMakeLists.txt
	ports/esp32/components/*/CMakeLists.txt
	tests/on_target/esp32/ultrawidelock-device-ec/main/CMakeLists.txt
)

# Upstream has never heard of us, so no line a patch does not add may say our
# name. Header, context and removal lines all have to match the pristine tree
# byte for byte or `git apply` fails, and bootstrap is the only thing that
# would have found out.
check_patch_upstream() {
	local list
	list="$(git grep -invE '^\+' -- integrations/nrfconnect-door-lock/patches |
		grep -iE 'ultrawidelock' || true)"
	if [ -n "$list" ]; then
		printf '%s\n' "$list" | sed "s/^/$R  ours in upstream text: /;s/\$/$Z/" >&2
		printf '%scheck-purity: %d patch line(s) outside a + rename upstream text%s\n' \
			"$R" "$(printf '%s\n' "$list" | wc -l | tr -d ' ')" "$Z" >&2
		return 1
	fi
	printf '%s  ok   patches: upstream headers and context never name ultrawidelock%s\n' "$G" "$Z"
}

check_build_paths() {
	local fails=0 n=0 mods=0 f p
	for f in "${BUILD_FILES[@]}"; do
		while IFS= read -r p; do
			n=$((n + 1))
			if [ ! -e "$p" ]; then
				printf '%s  missing path: %s (named by %s)%s\n' "$R" "$p" "$f" "$Z" >&2
				fails=$((fails + 1))
			fi
		done < <(cmake_path_list "$f")
	done
	while IFS= read -r p; do
		n=$((n + 1))
		mods=$((mods + 1))
		if [ ! -d "$p" ]; then
			printf '%s  missing module dir: %s (-D*ZEPHYR*_MODULES in scripts/ or mk/)%s\n' \
				"$R" "$p" "$Z" >&2
			fails=$((fails + 1))
		fi
	done < <(module_list_paths)
	if [ "$fails" -gt 0 ]; then
		printf '%scheck-purity: %d dangling build-file path(s) — the Zephyr/ESP builds cannot prove them here%s\n' \
			"$R" "$fails" "$Z" >&2
		return 1
	fi
	# Counted apart from n on purpose. n aggregates two selectors, so breaking
	# only the -D*_MODULES grep drops it from 322 to 313 -- still comfortably
	# non-zero, still reported as ok, with nine module paths silently unchecked.
	# A floor on the total cannot see a selector that goes half blind; only a
	# floor on each selector can.
	selector_live "cmake path literals" "$((n - mods))" || return 1
	selector_live "build-file module paths" "$mods" || return 1
	printf '%s  ok   build-file paths: %d literal(s) resolve in the tree%s\n' "$G" "$n" "$Z"
}

# ---- persistent storage names ------------------------------------------------
#
# Every framework caps the names of its persistent records, and ESP-IDF's NVS is
# the one that does not say so: a read-only open of an over-long namespace misses
# as NOT_FOUND, indistinguishable from "never stored", and only the write side
# reports KEY_TOO_LONG. A rename took the provisioning namespace to 18 characters
# and that asymmetry carried it through the host suite and a release to a bench
# session (docs/esp32-gotchas.md 8.4).
#
# The names are declared in the ports, listed in PORTING.md's storage table, and
# bound together here: over the cap fails, listed-but-absent fails, and a call
# site in a file the table does not list fails. Compile-time asserts guard the
# ESP32 names too, but only on a bench that has ESP-IDF; this runs anywhere.
STORAGE_TABLE=PORTING.md

storage_cap_for() { # port -> the longest name it may store, empty if unknown
	case "$1" in
	# NVS_NS_NAME_MAX_SIZE - 1 and NVS_KEY_NAME_MAX_SIZE - 1, ESP-IDF nvs.h.
	esp32) printf '15' ;;
	# SETTINGS_MAX_NAME_LEN = 8 * SETTINGS_MAX_DIR_DEPTH, zephyr settings.h.
	zephyr) printf '64' ;;
	*) printf '' ;;
	esac
}

# The freertos-nrf52833 port is absent on purpose: its records are numeric ids in
# windowed ranges, so it has no name to measure. It also implements the settings
# API for Matter, and those definitions are not call sites.
STORAGE_ZEPHYR_SCOPE=(ports apps examples ':!ports/freertos-nrf52833')

storage_name_bad() { # port, name -> reason on stdout, 0 if the name is unusable
	local port="$1" name="$2" cap depth
	cap="$(storage_cap_for "$port")"
	if [ -z "$cap" ]; then
		printf 'no cap known for port %s' "$port"
		return 0
	fi
	if [ "${#name}" -gt "$cap" ]; then
		printf '%d characters, over the %s cap of %s' "${#name}" "$port" "$cap"
		return 0
	fi
	if [ "$port" = zephyr ]; then
		# SETTINGS_MAX_DIR_DEPTH levels, separators included in the name.
		depth=$(printf '%s' "$name" | tr -cd '/' | wc -c | tr -d ' ')
		if [ "$((depth + 1))" -gt 8 ]; then
			printf '%d levels, over the settings depth of 8' "$((depth + 1))"
			return 0
		fi
	fi
	return 1
}

storage_rows() { # -> "port|kind|name|cap|file" for each listed record
	sed -n '/<!-- storage-names:begin -->/,/<!-- storage-names:end -->/p' "$STORAGE_TABLE" |
		grep -E '^\| *(esp32|zephyr) *\|' |
		sed -E 's/^\| *//; s/ *\|[[:space:]]*$//; s/ *\| */|/g; s/`//g'
}

storage_call_sites() { # -> every file that names a persistent record
	git grep -lE 'nvs_open\(' -- ports apps examples
	# Call sites, not the freertos shim's definitions of the same symbols.
	git grep -lE '(settings_save_one|settings_delete|settings_load_subtree|SETTINGS_STATIC_HANDLER_DEFINE)\(' \
		-- "${STORAGE_ZEPHYR_SCOPE[@]}"
}

storage_inline_keys() { # -> "path:line:name" for keys written at the call site
	git grep -nEo 'nvs_(get|set)_(str|blob|u8|i8|u16|i16|u32|i32|u64|i64)\([^,]+, *"[^"]*"' \
		-- ports apps examples |
		sed -E 's/^([^:]+:[0-9]+):.*, *"([^"]*)"$/\1:\2/'
}

check_storage_names() {
	local fails=0 rows=0 sites=0 inline=0 row port kind name cap file why f
	while IFS='|' read -r port kind name cap file; do
		[ -n "$port" ] || continue
		rows=$((rows + 1))
		if [ "$cap" != "$(storage_cap_for "$port")" ]; then
			printf '%s  %s "%s": table says cap %s, the port says %s%s\n' \
				"$R" "$port" "$name" "$cap" "$(storage_cap_for "$port")" "$Z" >&2
			fails=$((fails + 1))
		fi
		if why="$(storage_name_bad "$port" "$name")"; then
			printf '%s  %s "%s": %s%s\n' "$R" "$port" "$name" "$why" "$Z" >&2
			fails=$((fails + 1))
		fi
		if [ ! -f "$file" ]; then
			printf '%s  %s "%s": declared in %s, which is not in the tree%s\n' \
				"$R" "$port" "$name" "$file" "$Z" >&2
			fails=$((fails + 1))
		elif ! grep -qF "\"$name\"" "$file"; then
			printf '%s  %s "%s": %s no longer spells it — renamed in code, not in %s%s\n' \
				"$R" "$port" "$name" "$file" "$STORAGE_TABLE" "$Z" >&2
			fails=$((fails + 1))
		fi
	done < <(storage_rows)

	# The other direction: a port that starts storing something has to say so.
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		sites=$((sites + 1))
		if ! storage_rows | grep -F "|$f" >/dev/null; then
			printf '%s  %s stores a record under a name %s does not list%s\n' \
				"$R" "$f" "$STORAGE_TABLE" "$Z" >&2
			fails=$((fails + 1))
		fi
	done < <(storage_call_sites | sort -u)

	# Keys written at the call site are never declared, so the table cannot hold
	# them; the cap still does.
	while IFS= read -r row; do
		[ -n "$row" ] || continue
		inline=$((inline + 1))
		name="${row##*:}"
		if why="$(storage_name_bad esp32 "$name")"; then
			printf '%s  %s: inline NVS key "%s": %s%s\n' \
				"$R" "${row%:*}" "$name" "$why" "$Z" >&2
			fails=$((fails + 1))
		fi
	done < <(storage_inline_keys)

	if [ "$fails" -gt 0 ]; then
		printf '%scheck-purity: %d persistent storage name(s) the flash would not hold or %s does not list%s\n' \
			"$R" "$fails" "$STORAGE_TABLE" "$Z" >&2
		return 1
	fi
	# Each selector counted apart: a table that stops parsing still leaves the
	# call-site scan green, and that combination is exactly the silence this
	# check exists to break.
	selector_live "storage table rows" "$rows" || return 1
	selector_live "storage call sites" "$sites" || return 1
	selector_live "inline NVS keys" "$inline" || return 1
	printf '%s  ok   storage names: %d listed record(s) + %d inline key(s) fit their caps, %d call site(s) listed%s\n' \
		"$G" "$rows" "$inline" "$sites" "$Z"
}

# ---- patch-symbol tripwire ---------------------------------------------------
#
# Identifier shapes a Nordic-add-on patch grafts in. A rename in modules/ or
# ports/ leaves the patch applying cleanly and breaks only at add-on build
# time, on hardware CI. Fail here instead.
PATCH_SYM_RE='ultrawidelock_[a-z0-9_]+|UltraWideLockNfc::[A-Za-z]+|CONFIG_ULTRAWIDELOCK_[A-Z0-9_]+'
PATCH_HEADER_RE='ultrawidelock/[a-z0-9_]+[.]h'
# Names a patch itself coins rather than references (never defined in-tree).
PATCH_LOCAL_RE='^ultrawidelock_uwb_impl$' # LOG_MODULE name local to custom_impl-uwb.patch

patch_syms() { # <patch> -> unique ultrawidelock identifiers on its + lines
	grep -E '^\+' "$1" | grep -oE "$PATCH_SYM_RE" | LC_ALL=C sort -u
}

patch_headers() { # <patch> -> unique public SDK headers on its + lines
	grep -E '^\+' "$1" | grep -oE "$PATCH_HEADER_RE" | LC_ALL=C sort -u
}

patch_definition_files() {
	repo_files 'modules/*' 'ports/*' |
		grep -vE '^(modules/ultrawidelock_dw3000/dwt_uwb_driver/|modules/ultrawidelock_dfu/src/detools/)'
}

patch_sym_defined() { # <sym> -> 0 if modules/ or ports/ still carries it
	local f m ns hits=''
	case "$1" in
	UltraWideLockNfc::*)
		# In-tree the methods live inside `namespace UltraWideLockNfc { ... }`, so the
		# qualified spelling never appears; require one file naming both.
		ns=${1%%::*}
		m=${1##*::}
		while IFS= read -r f; do
			grep -qF "$ns" "$f" && hits="$hits $f"
		done < <(patch_definition_files)
		[ -n "$hits" ] || return 1
		# shellcheck disable=SC2086 # tracked paths, no whitespace
		grep -qlE "(^|[^[:alnum:]_])${m}([^[:alnum:]_]|\$)" $hits
		;;
	*)
		while IFS= read -r f; do
			grep -qF "$1" "$f" && return 0
		done < <(patch_definition_files)
		return 1
		;;
	esac
}

patch_header_defined() { # <ultrawidelock/header.h>
	local f
	while IFS= read -r f; do
		case "$f" in
		include/"$1" | */include/"$1") return 0 ;;
		esac
	done < <(repo_files 'include/ultrawidelock/*.h' 'modules/*/include/ultrawidelock/*.h')
	return 1
}

check_patch_symbols() {
	local fails=0 headers=0 n=0 p sym
	for p in integrations/nrfconnect-door-lock/patches/*.patch; do
		while IFS= read -r sym; do
			[ -n "$sym" ] || continue
			[[ $sym =~ $PATCH_LOCAL_RE ]] && continue
			n=$((n + 1))
			if ! patch_sym_defined "$sym"; then
				printf '%s  dangling patch symbol: %s (grafted by %s)%s\n' \
					"$R" "$sym" "$p" "$Z" >&2
				fails=$((fails + 1))
			fi
		done < <(patch_syms "$p")
		while IFS= read -r sym; do
			[ -n "$sym" ] || continue
			headers=$((headers + 1))
			if ! patch_header_defined "$sym"; then
				printf '%s  dangling patch header: %s (grafted by %s)%s\n' \
					"$R" "$sym" "$p" "$Z" >&2
				fails=$((fails + 1))
			fi
		done < <(patch_headers "$p")
	done
	if [ "$fails" -gt 0 ]; then
		printf '%scheck-purity: %d patch contract reference(s) no longer defined%s\n' \
			"$R" "$fails" "$Z" >&2
		return 1
	fi
	selector_live "patch contract symbols" "$n" || return 1
	printf '%s  ok   add-on patches: %d ultrawidelock symbol(s), %d SDK header(s) still defined%s\n' \
		"$G" "$n" "$headers" "$Z"
}

# ---- role manifests ----------------------------------------------------------
#
# Trees whose every tracked .c must be assigned to a role. Deliberately not the
# whole of modules/: the vendored decadriver is reached BY manifests (core.list
# points into it) but is not ours to enumerate, and single-port modules
# (ultrawidelock_matter, ultrawidelock_ml, ...) have one consumer each, so a manifest
# would be a second copy of a list that exists once.
#
# ultrawidelock_anchor joined the list when the satellite went to ESP32: the same geometry
# and the same WV3 codec now compile under Zephyr, ESP-IDF and the host cc, and
# a second consumer is exactly the condition a manifest exists to serve.
MANIFEST_ROOTS=(
	modules/ultrawidelock_anchor/src
	modules/ultrawidelock_cred/src
	modules/ultrawidelock_uwb/src
)

# Shared sources deliberately left out of every role, with the reason. Same
# ratchet discipline as RATCHET: an entry that becomes manifested, or stops
# existing, is a FAILURE — the allowlist can only shrink deliberately.
#
#   ultrawidelock_stepup.c      the step-up verifier; the ESP reader component compiles
#                       it always (its worker body is gated to empty without
#                       CONFIG_ULTRAWIDELOCK_CRED_STEPUP) and the DWM3001CDK app only
#                       under that option, so neither role list can carry it
#   ultrawidelock_assert_ec.c   the P-256 half of the assert pair — the only one with a
#                       crypto dependency, so it cannot join wire_codecs
#   uwb_rxdiag.c        Zephyr-module only: the ESP port omits it and stubs the
#                       two decadriver seams it would otherwise supply
#   uwb_selftest.c      Zephyr-module only, CONFIG_ULTRAWIDELOCK_UWB_SELFTEST, default n
NOT_MANIFESTED=(
	modules/ultrawidelock_cred/src/ultrawidelock_assert_ec.c
	modules/ultrawidelock_cred/src/ultrawidelock_stepup.c
	modules/ultrawidelock_uwb/src/driver/uwb_rxdiag.c
	modules/ultrawidelock_uwb/src/driver/uwb_selftest.c
)

manifest_files() { repo_files 'modules/*/roles/*.list'; }

# One manifest -> its repo-relative paths, comments and blank lines dropped.
# The same three rules cmake/ultrawidelock_roles.cmake and tests/host/sources.sh apply.
manifest_paths() {
	sed -e 's/#.*//' -e 's/[[:space:]]//g' -e '/^$/d' "$@"
}

check_manifests() {
	local fails=0 n=0 lists=0 f p dup root

	# Both selectors below pass by finding nothing. If modules/*/roles/*.list
	# stops matching, every list "resolves" because there are none; if a
	# MANIFEST_ROOTS entry stops matching, the coverage loop walks fewer sources
	# and still reports ok. A rename breaks both at once and in the same commit,
	# which is the one situation where their silence is correlated. So each
	# selector has to answer for itself before its result is trusted.
	if [ "$(manifest_files | wc -l | tr -d ' ')" -eq 0 ]; then
		printf '%s  no role manifests matched modules/*/roles/*.list%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	for root in "${MANIFEST_ROOTS[@]}"; do
		[ -d "$root" ] || {
			printf '%s  manifest root gone: %s%s\n' "$R" "$root" "$Z" >&2
			fails=$((fails + 1))
			continue
		}
		[ -n "$(repo_files "$root/*.c")" ] || {
			printf '%s  manifest root has no tracked .c: %s%s\n' "$R" "$root" "$Z" >&2
			fails=$((fails + 1))
		}
	done

	while IFS= read -r f; do
		lists=$((lists + 1))
		while IFS= read -r p; do
			n=$((n + 1))
			if [ ! -f "$p" ]; then
				printf '%s  missing manifest path: %s (listed by %s)%s\n' \
					"$R" "$p" "$f" "$Z" >&2
				fails=$((fails + 1))
			fi
		done < <(manifest_paths "$f")
	done < <(manifest_files)

	# A file in two roles is compiled twice by any consumer taking both.
	while IFS= read -r dup; do
		[ -n "$dup" ] || continue
		printf '%s  source in two roles: %s%s\n' "$R" "$dup" "$Z" >&2
		fails=$((fails + 1))
		# shellcheck disable=SC2046 # tracked manifest paths, no whitespace
	done < <(manifest_paths $(manifest_files) | LC_ALL=C sort | uniq -d)

	if [ "$fails" -gt 0 ]; then
		printf '%scheck-purity: %d broken role manifest entr(ies)%s\n' "$R" "$fails" "$Z" >&2
		return 1
	fi
	printf '%s  ok   role manifests: %d list(s), %d path(s), all resolve, none doubled%s\n' \
		"$G" "$lists" "$n" "$Z"

	# Coverage: every shared source is in a role or on the allowlist.
	local manifested allow src stale=0
	# shellcheck disable=SC2046 # tracked manifest paths, no whitespace
	manifested=$(manifest_paths $(manifest_files) | LC_ALL=C sort -u)
	allow=$(printf '%s\n' "${NOT_MANIFESTED[@]}" | LC_ALL=C sort -u)
	while IFS= read -r src; do
		[ -n "$src" ] || continue
		printf '%s\n' "$manifested" | grep -xF "$src" >/dev/null && continue
		printf '%s\n' "$allow" | grep -xF "$src" >/dev/null && continue
		printf '%s  unmanifested shared source: %s%s\n' "$R" "$src" "$Z" >&2
		fails=$((fails + 1))
	done < <(repo_files "${MANIFEST_ROOTS[@]/%//*.c}")

	for src in "${NOT_MANIFESTED[@]}"; do
		if [ ! -f "$src" ] || printf '%s\n' "$manifested" | grep -xF "$src" >/dev/null; then
			printf '%s  stale NOT_MANIFESTED entry: %s%s\n' "$R" "$src" "$Z" >&2
			stale=$((stale + 1))
		fi
	done

	if [ "$fails" -gt 0 ] || [ "$stale" -gt 0 ]; then
		[ "$fails" -eq 0 ] || printf '%scheck-purity: %d shared source(s) in no role — add to a roles/*.list or to NOT_MANIFESTED with a reason%s\n' \
			"$R" "$fails" "$Z" >&2
		[ "$stale" -eq 0 ] || printf '%scheck-purity: %d stale NOT_MANIFESTED entr(ies) — shrink the list%s\n' \
			"$R" "$stale" "$Z" >&2
		return 1
	fi
	printf '%s  ok   role coverage: every shared source is in a role, %d allowlisted%s\n' \
		"$G" "${#NOT_MANIFESTED[@]}" "$Z"
}

# The installed HAL umbrella is deliberately small. Adding a sixth seam or
# dropping one of these five is an architecture change, not a header cleanup.
HAL_CONTRACT=modules/ultrawidelock_port/include/ultrawidelock/ultrawidelock_hal.h
HAL_CONTRACT_HEADERS=(
	ultrawidelock_ble.h
	ultrawidelock_ble_central.h
	ultrawidelock_prov.h
	dw3000_hw.h
	dw3000_spi.h
)

hal_contract_headers() {
	sed -nE 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*"([^"]+)".*/\1/p' "$1" |
		LC_ALL=C sort
}

hal_contract_matches() {
	local header="$1" got expected
	got=$(hal_contract_headers "$header")
	expected=$(printf '%s\n' "${HAL_CONTRACT_HEADERS[@]}" | LC_ALL=C sort)
	[ "$got" = "$expected" ]
}

check_hal_contract() {
	if [ ! -f "$HAL_CONTRACT" ] || ! hal_contract_matches "$HAL_CONTRACT"; then
		printf '%scheck-purity: ultrawidelock/ultrawidelock_hal.h must include exactly the five approved seam headers%s\n' \
			"$R" "$Z" >&2
		return 1
	fi
	printf '%s  ok   HAL contract: exactly five chipset seams%s\n' "$G" "$Z"
}

# ---- self-test --------------------------------------------------------------
#
# Plant each shape the scan must catch and each it must ignore; fail loudly on
# either. Then prove the exemptions are exact.

self_test() {
	local fails=0 line n=0 quiet=0

	local should_fire=(
		'#include <zephyr/kernel.h>'
		'  #include "freertos/FreeRTOS.h"'
		'  #include "FreeRTOS.h"'
		'#include <esp_timer.h>'
		'	k_work_submit(&ctx.work);'
		'	if (k_sem_take(&s, K_MSEC(50)) != 0) {'
		'	rc = flash_area_open(FIXED_PARTITION_ID(slot1), &fa);'
		'SYS_INIT(boost, PRE_KERNEL_1, 0);'
		'K_WORK_DELAYABLE_DEFINE(rearm, rearm_fn);'
		'	sys_reboot(SYS_REBOOT_COLD);'
		'	xTaskCreateStatic(entry, "worker", 128, NULL, 3, stack, &tcb);'
	)
	local should_not=(
		'	ultrawidelock_work_submit(&ctx.work);'
		'	ultrawidelock_sem_take(&s, 50);'
		'#include "ultrawidelock_port.h"'
		'	ultrawidelock_work_submit(&ctx.work);'
		'	ultrawidelock_sem_take(&s, 50);'
		'#include "ultrawidelock_port.h"'
		'#include <ultrawidelock/reader.h>'
		'	int task_sem = mask_semantics(x);'
		'	stack_free(p);'
		'#define ESP_NOTE 1 /* not an include */'
	)

	for line in "${should_fire[@]}"; do
		if printf '%s\n' "$line" | grep -E "$INCLUDE_RE|$KERNEL_RE" >/dev/null; then
			n=$((n + 1))
		else
			printf '%s  self-test FAILED: missed: %s%s\n' "$R" "$line" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	[ "$fails" -ne 0 ] || printf '%s  self-test: detector fires on all %d impure shapes%s\n' "$G" "$n" "$Z"

	for line in "${should_not[@]}"; do
		if printf '%s\n' "$line" | grep -E "$INCLUDE_RE|$KERNEL_RE" >/dev/null; then
			printf '%s  self-test FAILED: fired on a legitimate line: %s%s\n' "$R" "$line" "$Z" >&2
			fails=$((fails + 1))
		else
			quiet=$((quiet + 1))
		fi
	done
	[ "$fails" -ne 0 ] || printf '%s  self-test: quiet on all %d legitimate shapes%s\n' "$G" "$quiet" "$Z"

	# Crypto-provider boundary: raw provider includes and calls must fire, while
	# the portable primitive call and the one exact provider path remain valid.
	local crypto_bad=('#include <psa/crypto.h>' '#include "mbedtls/aes.h"'
		'psa_crypto_init();' 'mbedtls_aes_crypt_ecb(&ctx, 1, in, out);'
		'EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);'
		'wolfSSL_EVP_Cipher(ctx, out, in, len);')
	local crypto_ok=('ultrawidelock_aes_ecb_encrypt(key, 128u, in, out);'
		'ultrawidelock_random(nonce, sizeof(nonce));')
	for line in "${crypto_bad[@]}"; do
		if ! printf '%s\n' "$line" | grep -E "$CRYPTO_INCLUDE_RE|$CRYPTO_CALL_RE" >/dev/null; then
			printf '%s  self-test FAILED: crypto boundary missed: %s%s\n' \
				"$R" "$line" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	for line in "${crypto_ok[@]}"; do
		if printf '%s\n' "$line" | grep -E "$CRYPTO_INCLUDE_RE|$CRYPTO_CALL_RE" >/dev/null; then
			printf '%s  self-test FAILED: crypto boundary rejected a primitive call: %s%s\n' \
				"$R" "$line" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	if ! crypto_path_allowed "$CRYPTO_PROVIDER" || \
		crypto_path_allowed modules/ultrawidelock_uwb/src/ccc/ccc_crypto_prim.c; then
		printf '%s  self-test FAILED: crypto provider exception is not exact%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	[ "$fails" -ne 0 ] || printf '%s  self-test: crypto boundary rejects raw providers and accepts primitive calls%s\n' \
		"$G" "$Z"

	# HAL exactness: both a missing seam and an invented sixth seam must fail,
	# while the approved five pass independently of include order.
	local halfix
	halfix=$(mktemp -t purity-hal.XXXXXX)
	printf '%s\n' '#include "ultrawidelock_ble.h"' '#include "ultrawidelock_ble_central.h"' \
		'#include "ultrawidelock_prov.h"' '#include "dw3000_hw.h"' >"$halfix"
	if hal_contract_matches "$halfix"; then
		printf '%s  self-test FAILED: HAL contract accepted a missing seam%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	printf '%s\n' '#include "dw3000_spi.h"' '#include "ultrawidelock_ble.h"' \
		'#include "ultrawidelock_ble_central.h"' '#include "ultrawidelock_prov.h"' \
		'#include "dw3000_hw.h"' '#include "invented_bus.h"' >"$halfix"
	if hal_contract_matches "$halfix"; then
		printf '%s  self-test FAILED: HAL contract accepted an extra seam%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	printf '%s\n' '#include "dw3000_spi.h"' '#include "ultrawidelock_ble.h"' \
		'#include "ultrawidelock_ble_central.h"' '#include "ultrawidelock_prov.h"' \
		'#include "dw3000_hw.h"' >"$halfix"
	if ! hal_contract_matches "$halfix"; then
		printf '%s  self-test FAILED: HAL contract rejected the approved seams%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	rm -f "$halfix"
	[ "$fails" -ne 0 ] || printf '%s  self-test: HAL contract rejects missing and extra seams%s\n' "$G" "$Z"

	# Storage caps: the boundary in both directions, per port. "at the cap" is
	# the case worth pinning -- an off-by-one here reads as a passing gate, and
	# the whole point of the check is that the flash will not say so.
	local storage_bad=('esp32|sixteen_chars_ns' 'esp32|blob_with_a_long_name'
		'zephyr|a/b/c/d/e/f/g/h/i'
		'zephyr|0123456789012345678901234567890123456789012345678901234567890123456789'
		'nrf9160|anything')
	local storage_ok=('esp32|uwl_prov' 'esp32|fifteen_chars_n' 'esp32|blob'
		'zephyr|ultrawidelock/prov' 'zephyr|a/b/c/d/e/f/g/h')
	local port name
	for line in "${storage_bad[@]}"; do
		port="${line%%|*}"
		name="${line#*|}"
		if ! storage_name_bad "$port" "$name" >/dev/null; then
			printf '%s  self-test FAILED: storage cap accepted %s "%s"%s\n' \
				"$R" "$port" "$name" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	for line in "${storage_ok[@]}"; do
		port="${line%%|*}"
		name="${line#*|}"
		if storage_name_bad "$port" "$name" >/dev/null; then
			printf '%s  self-test FAILED: storage cap rejected a usable %s "%s"%s\n' \
				"$R" "$port" "$name" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	# The table has to parse into the five fields the check reads, or every row
	# check above quietly compares empty strings and passes.
	if [ "$(storage_rows | awk -F'|' 'NF == 5' | wc -l | tr -d ' ')" != \
		"$(storage_rows | wc -l | tr -d ' ')" ]; then
		printf '%s  self-test FAILED: %s rows do not parse into 5 fields%s\n' \
			"$R" "$STORAGE_TABLE" "$Z" >&2
		fails=$((fails + 1))
	fi
	[ "$fails" -ne 0 ] || printf '%s  self-test: storage caps hold at 15/64 and the table parses%s\n' "$G" "$Z"

	# Comment filter: drops prose, keeps code with a trailing comment.
	local drop=('12: * uses k_work_reschedule under the hood' '7://	k_msleep(5);')
	local keep='20:	ultrawidelock_sem_give(&s); /* not k_sem_give */'
	for line in "${drop[@]}"; do
		if ! printf '%s\n' "$line" | grep -E "$COMMENT_LINE_RE" >/dev/null; then
			printf '%s  self-test FAILED: comment filter kept: %s%s\n' "$R" "$line" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	if printf '%s\n' "$keep" | grep -E "$COMMENT_LINE_RE" >/dev/null; then
		printf '%s  self-test FAILED: comment filter dropped a line of code%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	[ "$fails" -ne 0 ] || printf '%s  self-test: comment filter drops prose, keeps code%s\n' "$G" "$Z"

	# Per-OS halves: each must fire on the other OS and stay quiet on its own,
	# or check_port_os would ban a tree from the platform it is written for.
	local zline='#include <zephyr/kernel.h>' eline='#include "freertos/task.h"'
	local fline='#include "task.h"'
	printf '%s\n' "$zline" | grep -E "$ZEPHYR_INC_RE" >/dev/null ||
		{ printf '%s  self-test FAILED: zephyr half missed its own include%s\n' "$R" "$Z" >&2
			fails=$((fails + 1)); }
	printf '%s\n' "$eline" | grep -E "$ESP_INC_RE" >/dev/null ||
		{ printf '%s  self-test FAILED: esp half missed its own include%s\n' "$R" "$Z" >&2
			fails=$((fails + 1)); }
	printf '%s\n' "$fline" | grep -E "$FREERTOS_INC_RE" >/dev/null ||
		{ printf '%s  self-test FAILED: FreeRTOS half missed its own include%s\n' "$R" "$Z" >&2
			fails=$((fails + 1)); }
	if printf '%s\n' "$zline" | grep -E "$ESP_INC_RE" >/dev/null; then
		printf '%s  self-test FAILED: esp half fired on a zephyr include%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	if printf '%s\n' "$eline" | grep -E "$ZEPHYR_INC_RE" >/dev/null; then
		printf '%s  self-test FAILED: zephyr half fired on an esp include%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	if printf '%s\n' "$fline" | grep -E "$ESP_INC_RE|$ZEPHYR_INC_RE" >/dev/null; then
		printf '%s  self-test FAILED: another OS half fired on a canonical FreeRTOS include%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	# The tree lists must be disjoint, and must not reach into modules/ or
	# tests/ — a tree in both lists could name neither OS and pass.
	local zt et
	for zt in "${ZEPHYR_TREES[@]}"; do
		for et in "${ESP_TREES[@]}" "${FREERTOS_TREES[@]}"; do
			case "$zt" in "$et" | "$et"/*) ;; *) continue ;; esac
			printf '%s  self-test FAILED: %s is in both OS tree lists%s\n' "$R" "$zt" "$Z" >&2
			fails=$((fails + 1))
		done
	done
	for zt in "${ESP_TREES[@]}"; do
		for et in "${FREERTOS_TREES[@]}"; do
			case "$zt" in "$et" | "$et"/*) ;; *) continue ;; esac
			printf '%s  self-test FAILED: %s is in both OS tree lists%s\n' "$R" "$zt" "$Z" >&2
			fails=$((fails + 1))
		done
	done
	for zt in "${ZEPHYR_TREES[@]}" "${ESP_TREES[@]}" "${FREERTOS_TREES[@]}"; do
		case "$zt" in
		modules | modules/* | tests | tests/*)
			printf '%s  self-test FAILED: %s is not a platform tree%s\n' "$R" "$zt" "$Z" >&2
			fails=$((fails + 1))
			;;
		esac
	done
	[ "$fails" -ne 0 ] || printf '%s  self-test: per-OS halves and tree lists are exact%s\n' "$G" "$Z"

	# Exemption exactness: a prefix that swallowed a portable file would silence
	# the gate without anyone noticing.
	local f
	for f in modules/ultrawidelock_matter/src/matter_tlv.c modules/ultrawidelock_cred/src/ultrawidelock_reader.c \
		modules/ultrawidelock_uwb/src/ccc/ccc_shim.c modules/ultrawidelock_dw3000/src/deca_port.c; do
		if [[ $f =~ $PERMANENT_RE ]] || in_ratchet "$f"; then
			printf '%s  self-test FAILED: %s is exempt, but it must stay pure%s\n' \
				"$R" "$f" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	[ "$fails" -ne 0 ] || printf '%s  self-test: exemptions cover only the declared adapters%s\n' "$G" "$Z"

	# ...and every declared exemption is still earning it: the staleness rule
	# the scan applies, re-run here so --self-test alone names the offender.
	for f in "${PERMANENT_FILES[@]}"; do
		if [ ! -f "$f" ]; then
			printf '%s  self-test FAILED: permanent exemption %s is gone%s\n' "$R" "$f" "$Z" >&2
			fails=$((fails + 1))
		elif [ -z "$(file_hits "$f")" ]; then
			printf '%s  self-test FAILED: permanent exemption %s is pure — drop it%s\n' \
				"$R" "$f" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	for f in "${PERMANENT_DIRS[@]}"; do
		if [ ! -d "$f" ]; then
			printf '%s  self-test FAILED: permanent exemption %s/ is gone%s\n' "$R" "$f" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	# The compiled regex must match exactly what the two lists declare — a
	# quoting slip there would silently widen or void the exemption set.
	for f in "${PERMANENT_FILES[@]}" "${PERMANENT_DIRS[@]/%//x.c}"; do
		if ! [[ $f =~ $PERMANENT_RE ]]; then
			printf '%s  self-test FAILED: declared exemption %s does not match the compiled regex%s\n' \
				"$R" "$f" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	[ "$fails" -ne 0 ] || printf '%s  self-test: every declared exemption still trips the ban%s\n' "$G" "$Z"

	# Path extractor: resolves set() variables and REPO_ROOT, joins relative
	# sources, and stays quiet on comments, EXISTS probes, unresolved ${...}
	# and prose like "and/or".
	local fixdir out
	fixdir=$(mktemp -d -t purity-selftest.XXXXXX)
	mkdir "$fixdir/src" # the set() value itself is emitted and must resolve
	cat >"$fixdir/fix.cmake" <<-'EOF'
		set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
		target_sources(app PRIVATE ${SRC}/nope.c src/also.c ${REPO_ROOT}/modules/ghost/gone.c)
		# comment/only.c
		if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/maybe/absent.h")
		zephyr_include_directories(${UNDEFINED_VAR}/x and/or)
	EOF
	out=$(cmake_path_list "$fixdir/fix.cmake")
	local want
	for want in "$fixdir/src/nope.c" "$fixdir/src/also.c" "./modules/ghost/gone.c"; do
		if ! printf '%s\n' "$out" | grep -xF "$want" >/dev/null; then
			printf '%s  self-test FAILED: path extractor missed: %s%s\n' "$R" "$want" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	local nowant
	for nowant in only.c absent.h UNDEFINED_VAR and/or; do
		if printf '%s\n' "$out" | grep -F "$nowant" >/dev/null; then
			printf '%s  self-test FAILED: path extractor emitted: %s%s\n' "$R" "$nowant" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	# ...and the scan half must flag every emitted-but-absent path.
	local missing=0 pth
	while IFS= read -r pth; do
		[ -e "$pth" ] || missing=$((missing + 1))
	done <<<"$out"
	if [ "$missing" -ne 3 ]; then
		printf '%s  self-test FAILED: expected 3 missing fixture paths, saw %d%s\n' \
			"$R" "$missing" "$Z" >&2
		fails=$((fails + 1))
	fi
	[ "$fails" -ne 0 ] || printf '%s  self-test: path extractor resolves, joins and filters correctly%s\n' "$G" "$Z"

	# Public include parser: all three propagated CMake forms fire, while their
	# private counterparts stay quiet.
	cat >"$fixdir/public.cmake" <<-'EOF'
		set(PUB ${REPO_ROOT}/modules/public/src)
		zephyr_include_directories(${PUB})
		zephyr_library_include_directories(${REPO_ROOT}/modules/library_private/src)
		target_include_directories(app PUBLIC ${REPO_ROOT}/modules/target/src
			PRIVATE ${REPO_ROOT}/modules/target_private/src)
		idf_component_register(
			SRCS x.c
			INCLUDE_DIRS ${REPO_ROOT}/modules/idf/src
			PRIV_INCLUDE_DIRS ${REPO_ROOT}/modules/idf_private/src)
	EOF
	out=$(cmake_public_include_list "$fixdir/public.cmake")
	if [ "$out" != "$(printf './modules/public/src\n./modules/target/src\n./modules/idf/src')" ]; then
		printf '%s  self-test FAILED: public include parser lost scope%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	[ "$fails" -ne 0 ] || printf '%s  self-test: public include scopes expose API paths only%s\n' "$G" "$Z"

	# Private-header matcher: an external source and a module API header must
	# trip, while a module implementation may include its own private sibling.
	local private_fix=(modules/ultrawidelock_alpha/src/secret.h modules/ultrawidelock_alpha/src/protocol/wire.h)
	if [ "$(private_header_target modules/ultrawidelock_beta/src/use.c secret.h "${private_fix[@]}")" != \
		"modules/ultrawidelock_alpha/src/secret.h" ]; then
		printf '%s  self-test FAILED: private header matcher missed a cross-module include%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	if [ "$(private_header_target ports/zephyr/use.c protocol/wire.h "${private_fix[@]}")" != \
		"modules/ultrawidelock_alpha/src/protocol/wire.h" ]; then
		printf '%s  self-test FAILED: private header matcher missed a qualified include%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	if [ "$(private_header_target modules/ultrawidelock_alpha/include/api.h secret.h "${private_fix[@]}")" != \
		"modules/ultrawidelock_alpha/src/secret.h" ]; then
		printf '%s  self-test FAILED: private header matcher missed a public-header leak%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	if private_header_target modules/ultrawidelock_alpha/src/impl.c secret.h "${private_fix[@]}" >/dev/null; then
		printf '%s  self-test FAILED: private header matcher rejected an owned sibling%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	local private_fix_uwl=(modules/ultrawidelock_alpha/src/secret.h)
	if private_header_target modules/ultrawidelock_alpha/src/impl.c secret.h \
		"${private_fix_uwl[@]}" >/dev/null; then
		printf '%s  self-test FAILED: private header matcher rejected an owned ultrawidelock sibling%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	if [ "$(private_header_target modules/ultrawidelock_alpha/include/api.h secret.h \
		"${private_fix_uwl[@]}")" != "modules/ultrawidelock_alpha/src/secret.h" ]; then
		printf '%s  self-test FAILED: private header matcher missed an ultrawidelock public-header leak%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	[ "$fails" -ne 0 ] || printf '%s  self-test: private header ownership distinguishes API, implementation and consumers%s\n' "$G" "$Z"

	# Patch tripwire: + lines only, all identifier and SDK-header shapes, and
	# the resolver must fail on invented contracts while passing real ones.
	cat >"$fixdir/fix.patch" <<-'EOF'
		--- a/x.cpp
		+++ b/x.cpp
		+	ultrawidelock_phantom_symbol_xyz();
		+	ultrawidelock_phantom_other_xyz();
		+	UltraWideLockNfc::Init();
		+	if (CONFIG_ULTRAWIDELOCK_CRED) {}
		+#include <ultrawidelock/uwb.h>
		+#include <ultrawidelock/phantom.h>
		-	ultrawidelock_minus_line_only();
	EOF
	if [ "$(patch_syms "$fixdir/fix.patch")" != \
		"$(printf 'CONFIG_ULTRAWIDELOCK_CRED\nUltraWideLockNfc::Init\nultrawidelock_phantom_other_xyz\nultrawidelock_phantom_symbol_xyz')" ]; then
		printf '%s  self-test FAILED: patch_syms extraction wrong for the fixture%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	for pth in ultrawidelock_phantom_symbol_xyz ultrawidelock_phantom_other_xyz; do
		if patch_sym_defined "$pth"; then
			printf '%s  self-test FAILED: tripwire resolved an invented symbol: %s%s\n' \
				"$R" "$pth" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	if [ "$(patch_headers "$fixdir/fix.patch")" != "$(printf 'ultrawidelock/phantom.h\nultrawidelock/uwb.h')" ]; then
		printf '%s  self-test FAILED: patch header extraction is incomplete%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	if patch_header_defined ultrawidelock/phantom.h || ! patch_header_defined ultrawidelock/uwb.h; then
		printf '%s  self-test FAILED: patch header tripwire accepted a phantom or lost UWB%s\n' \
			"$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	for pth in CONFIG_ULTRAWIDELOCK_CRED UltraWideLockNfc::Init; do
		if ! patch_sym_defined "$pth"; then
			printf '%s  self-test FAILED: tripwire lost a real symbol: %s%s\n' "$R" "$pth" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	[ "$fails" -ne 0 ] || printf '%s  self-test: patch tripwire fires on invented symbols and headers only%s\n' "$G" "$Z"

	# Manifest parser: comments (whole-line and trailing), blank lines and
	# stray whitespace vanish; nothing else does. Must agree with
	# cmake/ultrawidelock_roles.cmake and tests/host/sources.sh, which parse the same
	# files with different tools.
	printf '%s\n' '# a role manifest' '' 'modules/x/src/a.c' \
		'  modules/x/src/b.c  ' 'modules/x/src/c.c # why' '#modules/x/src/never.c' \
		>"$fixdir/fix.list"
	if [ "$(manifest_paths "$fixdir/fix.list")" != "$(printf 'modules/x/src/a.c\nmodules/x/src/b.c\nmodules/x/src/c.c')" ]; then
		printf '%s  self-test FAILED: manifest parser disagrees on the fixture%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	# ...and a doubled path must be visible to the duplicate detector.
	if [ "$(manifest_paths "$fixdir/fix.list" "$fixdir/fix.list" | LC_ALL=C sort | uniq -d | wc -l)" -ne 3 ]; then
		printf '%s  self-test FAILED: duplicate detector missed a doubled path%s\n' "$R" "$Z" >&2
		fails=$((fails + 1))
	fi
	# The allowlist is exact: a file that IS in a role must not be swallowed.
	for f in modules/ultrawidelock_cred/src/ultrawidelock_tlv.c modules/ultrawidelock_uwb/src/ccc/ccc_kdf.c; do
		if printf '%s\n' "${NOT_MANIFESTED[@]}" | grep -xF "$f" >/dev/null; then
			printf '%s  self-test FAILED: %s is allowlisted but lives in a role%s\n' \
				"$R" "$f" "$Z" >&2
			fails=$((fails + 1))
		fi
	done
	[ "$fails" -ne 0 ] || printf '%s  self-test: manifest parser and allowlist are exact%s\n' "$G" "$Z"
	rm -rf "$fixdir"

	# check_patch_upstream passes by finding nothing, and a pathspec that had
	# stopped matching any patch at all would look identical. Its own selector,
	# asked for the word upstream really does use, has to come back with the
	# whole corpus.
	#
	# The floor is 5 and used to be 20, because the corpus is four patches and
	# used to be fifteen: eleven of them became owned source under
	# integrations/nrfconnect-door-lock/. Lowering it is the honest move --
	# what this guards against is a pathspec that matches nothing, which arrives
	# as 0 whatever the corpus size, and a floor set above the real count fails
	# every run while claiming the gate is broken.
	local upstream_lines
	upstream_lines="$(git grep -invE '^\+' -- integrations/nrfconnect-door-lock/patches |
		grep -icE 'aliro' | tr -d ' ')"
	if [ "$upstream_lines" -lt 5 ]; then
		printf '%s  self-test FAILED: patch upstream scan reached only %s line(s)%s\n' \
			"$R" "$upstream_lines" "$Z" >&2
		fails=$((fails + 1))
	else
		printf '%s  self-test: patch upstream scan is live (%s upstream line(s) named aliro)%s\n' \
			"$G" "$upstream_lines" "$Z"
	fi

	if [ "$fails" -ne 0 ]; then
		printf '%scheck-purity: the gate itself is broken%s\n' "$R" "$Z" >&2
		return 2
	fi
	return 0
}

case "${1-}" in
--self-test)
	self_test
	;;
"")
	rc=0
	# The self-test runs here, not only under --self-test, because that flag was
	# passed by hand and nothing else. A stale fixture in it went unnoticed
	# through a whole rename, which is the rot it exists to catch.
	self_test || rc=1
	scan || rc=1
	check_crypto_boundary || rc=1
	check_port_os || rc=1
	check_public_includes || rc=1
	check_private_headers || rc=1
	check_manifests || rc=1
	check_hal_contract || rc=1
	check_build_paths || rc=1
	check_storage_names || rc=1
	check_patch_symbols || rc=1
	check_patch_upstream || rc=1
	exit "$rc"
	;;
*)
	printf 'usage: %s [--self-test]\n' "$0" >&2
	exit 2
	;;
esac
