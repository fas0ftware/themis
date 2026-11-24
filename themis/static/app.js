"use strict";
// Every value is inserted with textContent: events quote SSH user names and device names.
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
const when = (ts) => new Date(ts * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "short" });
async function get(p) { const r = await fetch(p); if (!r.ok) throw new Error(`${p}: ${r.status}`); return r.json(); }

function list(id, items, render, empty) {
  const ul = $(id); ul.replaceChildren();
  for (const x of items) ul.append(render(x));
  if (!items.length) ul.append(el("li", empty, "muted"));
}

async function load() {
  const [o, events] = await Promise.all([get("/api/overview"), get(`/api/events?days=${$("days").value}&min=${$("min").value}`)]);
  $("ver").textContent = `v${o.version}`;
  const v = $("verdict"); v.textContent = o.verdict; v.className = `badge ${o.verdict}`;
  const c = o.counts || {};
  $("c-high").textContent = (c.high || 0) + (c.critical || 0);
  $("c-medium").textContent = c.medium || 0;
  $("c-low").textContent = c.low || 0;
  $("c-known").textContent = o.usb.length;
  $("c-known-sub").textContent = `USB devices · ${o.ports.length} ports · ${o.services} services known`;
  const ol = $("events"); ol.replaceChildren();
  for (const e of events) {
    const li = el("li", undefined, `sev-${e.severity}`);
    li.append(el("span", e.severity, "sev"), el("span", e.message, "msg"), el("time", `${when(e.ts)} · ${e.kind}`));
    ol.append(li);
  }
  if (!events.length) ol.append(el("li", "Nothing in this period.", "muted"));
  list("ports", o.ports, (p) => el("li", p.label || p.key), "none yet");
  list("usb", [...o.usb].reverse(), (u) => { const li = el("li", u.label || u.key); li.append(el("small", ` first seen ${when(u.first_seen)}`, "muted")); return li; }, "none yet");
  list("ignore", o.ignore, (r) => el("li", `#${r.id} ${r.kind}${r.match ? ` "${r.match}"` : ""}`), "No rules.");
}

document.addEventListener("DOMContentLoaded", () => {
  for (const id of ["days", "min"]) $(id).addEventListener("change", load);
  load().catch((e) => { $("verdict").textContent = "unreachable"; console.error(e); });
  setInterval(() => load().catch(() => {}), 30000);
});
