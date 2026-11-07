"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const results = byId("results");
  const filters = byId("filters");
  const programFilter = byId("program-filter");
  const machineFilter = byId("machine-filter");
  const threadFilter = byId("thread-filter");
  const sortOrder = byId("sort-order");
  const categoryBrowser = byId("category-browser");
  const categories = {
    client: { name: "Client-side proving", description: "On-device proving on Pixel and iPhone." },
    consensus: { name: "Consensus layer", description: "leanXMSS, leanSPHINCS and aggregation workloads, excluding on-device results." },
    data: { name: "Data layer", description: "leanDA workloads." },
    misc: { name: "Misc", description: "Other workloads, kept together until they find a home." },
    all: { name: "All benchmarks", description: "Every published configuration, grouped by use case." },
  };
  let selectedCategory = "client";
  const numberFormat = new Intl.NumberFormat("en", { maximumFractionDigits: 6 });
  const memoryFormat = new Intl.NumberFormat("en", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const dateFormat = new Intl.DateTimeFormat("en", {
    year: "numeric", month: "short", day: "numeric", timeZone: "UTC",
  });
  let measurements = [];

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function text(value, fallback = "Not recorded") {
    return typeof value === "string" && value.trim() ? value : fallback;
  }

  function cpuName(value) {
    return /^ARM implementer 0x41, part 0xd4f, revision \d+$/i.test(value)
      ? "Arm Neoverse V2" : text(value);
  }

  function machineName(machine) {
    return cpuName(text(machine.name, machine.id));
  }

  function safeUrl(value) {
    if (typeof value !== "string" || !value.trim()) return null;
    try {
      const url = new URL(value);
      return ["https:", "http:"].includes(url.protocol) ? url.href : null;
    } catch {
      return null;
    }
  }

  function link(label, url, className) {
    const href = safeUrl(url);
    const node = element(href ? "a" : "span", className, label);
    if (href) {
      node.href = href;
      node.rel = "noopener noreferrer";
    }
    return node;
  }

  function timestamp(value) {
    if (typeof value !== "string" || !value.trim()) return null;
    const time = Date.parse(value);
    return Number.isFinite(time) ? time : null;
  }

  function dateNode(value, className, fallback) {
    const time = timestamp(value);
    if (time === null) return element("span", className, fallback);
    const node = element("time", className, dateFormat.format(time));
    node.dateTime = new Date(time).toISOString();
    node.title = `${new Date(time).toISOString()} (UTC)`;
    return node;
  }

  function seconds(value) {
    return value > 0 && value < 0.000001 ? value.toExponential(3) : numberFormat.format(value);
  }

  function threadLabel(row) {
    const count = row.threads?.count;
    return Number.isInteger(count) && count > 0
      ? `${count} ${count === 1 ? "thread" : "threads"}`
      : text(row.threads?.label, "Default (not recorded)");
  }

  function threadKey(row) {
    const count = row.threads?.count;
    return Number.isInteger(count) && count > 0 ? `count:${count}` : `label:${threadLabel(row)}`;
  }

  function categoryOf(row) {
    if (/^leanda\b/i.test(row.program.name)) return "data";
    if (/pixel|iphone/i.test(text(row.machine.name, row.machine.id))) return "client";
    if (/^lean(?:xmss|sphincs)\b/i.test(row.program.name) || row.category === "aggregation") return "consensus";
    return "misc";
  }

  function categoryRows() {
    return measurements.filter((row) => selectedCategory === "all" || categoryOf(row) === selectedCategory);
  }

  function populateFilters() {
    const sorted = categoryRows().sort(compareRows);
    populate(programFilter, new Map(sorted.map((row) => [row.program.name, row.program.name])), "All programs");
    populate(machineFilter, [...new Map(sorted.map((row) => [row.machine.id, machineName(row.machine)]))].sort((a, b) => a[1].localeCompare(b[1])), "All machines & devices");
    const threads = [...new Map(sorted.map((row) => [threadKey(row), threadLabel(row)]))];
    threads.sort((a, b) => a[1].localeCompare(b[1], "en", { numeric: true }));
    populate(threadFilter, threads, "All thread configurations");
  }

  function resetFilters() {
    programFilter.value = "";
    machineFilter.value = "";
    threadFilter.value = "";
    sortOrder.value = "program";
    render();
  }

  function details(label, child) {
    const node = element("details");
    node.append(element("summary", "", label), child);
    return node;
  }

  function hardwareId(machine) {
    return `hardware-${encodeURIComponent(machine.id)}`;
  }

  function hardwareDetails(machines) {
    const machine = machines[0];
    const list = element("dl", "hardware");
    const memoryValues = machines.map((entry) => entry.memory_bytes).filter((value) => typeof value === "number" && value > 0);
    let memory = "Not recorded";
    if (memoryValues.length) {
      const minimum = Math.min(...memoryValues);
      const maximum = Math.max(...memoryValues);
      memory = `${numberFormat.format(minimum / 1024 ** 3)} GiB`;
      if (minimum !== maximum) {
        memory += ` (observed ${minimum.toLocaleString("en")} to ${maximum.toLocaleString("en")} bytes)`;
      }
    }
    const fields = [
      ["CPU / SoC", cpuName(machine.cpu)],
      ["Architecture", text(machine.arch)],
      ["Operating system", text(machine.os)],
      ["Logical CPUs", Number.isInteger(machine.logical_cpus) && machine.logical_cpus > 0 ? String(machine.logical_cpus) : "Not recorded"],
      ["OS-visible RAM", memory],
    ];
    if (cpuName(machine.cpu) !== text(machine.cpu)) fields.push(["CPU identifier", machine.cpu]);
    for (const [label, value] of fields) list.append(element("dt", "", label), element("dd", "", value));
    const entry = details(machineName(machine), list);
    entry.id = hardwareId(machine);
    entry.className = "hardware-entry";
    return entry;
  }

  function revealHardwareReference() {
    const entry = byId(location.hash.slice(1));
    if (entry?.classList.contains("hardware-entry")) {
      entry.open = true;
      entry.scrollIntoView({ block: "start" });
    }
  }

  function updateHardwareReference() {
    const platforms = new Map();
    for (const row of measurements) {
      if (!platforms.has(row.machine.id)) platforms.set(row.machine.id, []);
      platforms.get(row.machine.id).push(row.machine);
    }
    const machines = [...platforms.values()];
    machines.sort((left, right) => machineName(left[0]).localeCompare(machineName(right[0])));
    byId("hardware-list").replaceChildren(...machines.map(hardwareDetails));
    byId("hardware-reference").hidden = machines.length === 0;
    revealHardwareReference();
  }

  function updateSnapshot(source) {
    const node = byId("snapshot-provenance");
    node.replaceChildren();
    node.hidden = source === null;
    if (source === null) return;
    const revision = link(source.commit.slice(0, 8), `https://github.com/${source.repository}/commit/${source.commit}`, "revision");
    revision.title = source.commit;
    revision.setAttribute("aria-label", `Snapshot revision ${source.commit}`);
    node.append(element("span", "", source.branch), revision, link("Benchmark run ↗", source.run_url));
  }

  function measurementDetails(rows) {
    const metadata = element("div");
    for (const row of rows) metadata.append(measurementSamples(row));
    return details("Measurement details", metadata);
  }

  function measurementSamples(row) {
    const panel = element("section", "sample-set");
    panel.append(element("h5", "", `${threadLabel(row)}: ${row.samples_seconds.length} recorded ${row.samples_seconds.length === 1 ? "sample" : "samples"}`));
    panel.append(dateNode(row.measured_at, "measured-at", "Measurement date not recorded"));
    const range = element("p", "range", `${seconds(row.min_seconds)} to ${seconds(row.max_seconds)} s`);
    range.append(element("span", "range-label", "Observed min to max"));
    const samples = element("ol", "samples");
    for (const sample of row.samples_seconds) samples.append(element("li", "", `${sample} s`));
    panel.append(range, samples);
    panel.append(element("p", "memory-method", `Peak memory method: ${row.peak_memory_method}`));
    const verification = row.verification;
    if (Number.isInteger(verification?.verified_proofs) && Number.isInteger(verification?.total_proofs)
      && verification.verified_proofs >= 0 && verification.total_proofs > 0) {
      panel.append(element("span", "verification", `${verification.verified_proofs} / ${verification.total_proofs} proofs verified`));
    }
    return panel;
  }

  function resultWorkload(machineGroups) {
    const row = machineGroups[0][0];
    const section = element("section", "workload-section");
    const header = element("header", "workload-heading");
    const title = element("h3", "workload-title", row.program.name);
    title.id = `workload-${encodeURIComponent(row.id)}`;
    section.setAttribute("aria-labelledby", title.id);
    const description = element("div");
    description.append(title, element("p", "workload", row.workload));
    if (row.category === "aggregation") description.append(element("span", "category", "Aggregation workload"));
    if (selectedCategory === "all") {
      const category = categoryOf(row);
      description.append(element("span", `use-case ${category}`, categories[category].name));
    }
    header.append(description, link(safeUrl(row.program.source_url) ? "Program source ↗" : "Program source not recorded", row.program.source_url, "source-link"));
    section.append(header);
    for (const rows of machineGroups) section.append(resultMachine(rows));
    return section;
  }

  function resultMachine(rows) {
    const row = rows[0];
    const section = element("section", "machine-group");
    const context = element("div", "machine-context");
    const title = element("h4", "machine-title");
    title.id = `machine-${encodeURIComponent(row.id)}`;
    section.setAttribute("aria-labelledby", title.id);
    const reference = element("a", "machine-link", machineName(row.machine));
    reference.href = `#${hardwareId(row.machine)}`;
    reference.addEventListener("click", () => { byId(hardwareId(row.machine)).open = true; });
    title.append(reference);
    context.append(title, measurementDetails(rows));
    section.append(context, threadTable(rows));
    return section;
  }

  function threadTable(rows) {
    const table = element("table", "thread-table");
    const first = rows[0];
    table.append(element("caption", "visually-hidden", `Thread configurations for ${first.program.name}: ${first.workload}, on ${machineName(first.machine)}`));
    const head = element("thead");
    const headings = element("tr");
    for (const label of ["Threads", "Median (s)", "Peak memory (MiB)"]) {
      const heading = element("th", "", label);
      heading.scope = "col";
      headings.append(heading);
    }
    head.append(headings);
    const body = element("tbody");
    for (const row of rows) {
      const node = element("tr", "thread-row");
      const threads = element("th", "thread-count", threadLabel(row));
      threads.scope = "row";
      const runtime = element("td");
      const median = element("span", "timing", seconds(row.median_seconds));
      median.setAttribute("aria-label", `Median ${row.median_seconds} seconds`);
      runtime.append(median);
      const memory = element("td");
      const memoryMiB = memoryFormat.format(row.peak_memory_bytes / 1024 ** 2);
      const peak = element("span", "peak-memory", memoryMiB);
      peak.setAttribute("aria-label", `Peak memory ${memoryMiB} mebibytes`);
      peak.title = `${numberFormat.format(row.peak_memory_bytes)} bytes`;
      memory.append(peak);
      node.append(threads, runtime, memory);
      body.append(node);
    }
    table.append(head, body);
    return table;
  }

  function groupRows(rows) {
    const groups = new Map();
    for (const row of rows) {
      const key = JSON.stringify([
        row.program.name, row.program.source_url, row.workload, row.category,
        ...["id", "name", "arch", "os", "cpu", "logical_cpus"].map((field) => row.machine[field]),
      ]);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(row);
    }
    return groups.values();
  }

  function groupWorkloads(rows) {
    const workloads = new Map();
    for (const group of groupRows(rows)) {
      const row = group[0];
      const key = JSON.stringify([
        row.program.name, row.program.source_url, row.workload, row.category,
        categoryOf(row),
      ]);
      if (!workloads.has(key)) workloads.set(key, []);
      workloads.get(key).push(group);
    }
    return workloads.values();
  }

  function compareRows(left, right) {
    return left.program.name.localeCompare(right.program.name)
      || left.workload.localeCompare(right.workload, "en", { numeric: true })
      || machineName(left.machine).localeCompare(machineName(right.machine))
      || (left.threads?.count ?? Infinity) - (right.threads?.count ?? Infinity)
      || threadLabel(left).localeCompare(threadLabel(right))
      || left.id.localeCompare(right.id);
  }

  function render() {
    const available = categoryRows();
    const categoryOrder = Object.keys(categories);
    const shown = available.filter((row) =>
      (!programFilter.value || row.program.name === programFilter.value)
      && (!machineFilter.value || row.machine.id === machineFilter.value)
      && (!threadFilter.value || threadKey(row) === threadFilter.value));
    shown.sort((left, right) => {
      if (sortOrder.value === "recent") {
        const difference = (timestamp(right.measured_at) ?? -Infinity) - (timestamp(left.measured_at) ?? -Infinity);
        if (difference && !Number.isNaN(difference)) return difference;
      }
      if (selectedCategory === "all" && sortOrder.value === "program") {
        const difference = categoryOrder.indexOf(categoryOf(left)) - categoryOrder.indexOf(categoryOf(right));
        if (difference) return difference;
      }
      return compareRows(left, right);
    });
    const fragment = document.createDocumentFragment();
    for (const groups of groupWorkloads(shown)) fragment.append(resultWorkload(groups));
    byId("result-rows").replaceChildren(fragment);
    byId("result-rows").hidden = shown.length === 0;
    byId("empty-state").hidden = shown.length !== 0;
    const emptyDataset = measurements.length === 0;
    byId("empty-title").textContent = available.length === 0 ? "No published measurements yet." : "No matching measurements.";
    byId("empty-description").textContent = emptyDataset
      ? "A complete desktop, iPhone and Pixel run must finish before a snapshot is published."
      : available.length === 0
        ? `The current dataset has no measurements for ${categories[selectedCategory].name}.`
        : "Try a different program, machine or thread configuration.";
    byId("clear-filters").hidden = available.length === 0;
    byId("results-title").textContent = categories[selectedCategory].name;
    byId("category-description").textContent = categories[selectedCategory].description;
    byId("status").textContent = `${shown.length} of ${available.length} configurations · ${new Set(shown.map((row) => row.program.name)).size} programs · ${new Set(shown.map((row) => row.machine.id)).size} machines & devices`;
    for (const button of categoryBrowser.querySelectorAll("[data-category]")) {
      button.setAttribute("aria-pressed", String(button.dataset.category === selectedCategory));
    }
  }

  function populate(select, values, allLabel) {
    select.replaceChildren(element("option", "", allLabel));
    select.firstElementChild.value = "";
    for (const [value, label] of values) {
      const option = element("option", "", label);
      option.value = value;
      select.append(option);
    }
  }

  function updateCategoryCounts() {
    for (const category of Object.keys(categories)) {
      const count = category === "all" ? measurements.length : measurements.filter((row) => categoryOf(row) === category).length;
      byId(`${category}-count`).textContent = count;
      byId(`${category}-count`).setAttribute("aria-label", `${count} configurations`);
    }
  }

  function parseDataset(dataset) {
    if (!dataset || dataset.schema_version !== 3 || !Array.isArray(dataset.results)) throw new Error("Unsupported results format");
    const rows = dataset.results;
    if (rows.length === 0 && dataset.snapshot === null && dataset.generated_at === null) return rows;
    const source = dataset.snapshot;
    if (!rows.length || !source || !/^[\w.-]+\/[\w.-]+$/.test(source.repository)
      || source.branch !== "riscv-exploration" || !/^[a-f0-9]{40}$/.test(source.commit)
      || !Number.isSafeInteger(source.run_id) || source.run_id <= 0
      || source.run_url !== `https://github.com/${source.repository}/actions/runs/${source.run_id}`
      || timestamp(dataset.generated_at) === null) {
      throw new Error("Invalid snapshot provenance");
    }
    const sourcePrefix = `https://github.com/${source.repository}/blob/${source.commit}/`;
    const validTime = (value) => typeof value === "number" && Number.isFinite(value) && value > 0;
    const ids = new Set();
    for (const row of rows) {
      if (!row || !["program", "aggregation"].includes(row.category) || "source" in row
        || !text(row.id, "") || ids.has(row.id) || !text(row.program?.name, "") || !text(row.workload, "") || !text(row.machine?.id, "")
        || !text(row.program?.source_url, "").startsWith(sourcePrefix) || timestamp(row.measured_at) === null
        || ![row.median_seconds, row.min_seconds, row.max_seconds].every(validTime)
        || row.min_seconds > row.median_seconds || row.median_seconds > row.max_seconds
        || !Number.isSafeInteger(row.peak_memory_bytes) || row.peak_memory_bytes <= 0 || !text(row.peak_memory_method, "")
        || !Array.isArray(row.samples_seconds) || !row.samples_seconds.length || !row.samples_seconds.every(validTime)) {
        throw new Error("Invalid measurement record");
      }
      ids.add(row.id);
    }
    return rows;
  }

  async function load() {
    results.setAttribute("aria-busy", "true");
    byId("error-state").hidden = true;
    byId("empty-state").hidden = true;
    byId("result-rows").hidden = true;
    byId("hardware-reference").hidden = true;
    byId("snapshot-provenance").hidden = true;
    categoryBrowser.hidden = true;
    filters.hidden = true;
    byId("status").textContent = "Loading benchmark measurements…";
    try {
      const response = await fetch("./latest.json", { cache: "no-cache" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const dataset = await response.json();
      measurements = parseDataset(dataset);
      updateSnapshot(dataset.snapshot);
      populateFilters();
      sortOrder.value = "program";
      updateCategoryCounts();
      filters.hidden = measurements.length === 0;
      categoryBrowser.hidden = measurements.length === 0;
      render();
      updateHardwareReference();
    } catch {
      measurements = [];
      byId("result-rows").replaceChildren();
      byId("status").textContent = "Measurements unavailable. No cached or example results are being shown.";
      byId("error-state").hidden = false;
    } finally {
      results.setAttribute("aria-busy", "false");
    }
  }
  window.addEventListener("hashchange", revealHardwareReference);

  categoryBrowser.addEventListener("click", (event) => {
    const button = event.target.closest("[data-category]");
    if (!button || button.dataset.category === selectedCategory) return;
    selectedCategory = button.dataset.category;
    populateFilters();
    render();
  });
  filters.addEventListener("submit", (event) => event.preventDefault());
  filters.addEventListener("change", render);
  filters.addEventListener("reset", (event) => {
    event.preventDefault();
    resetFilters();
  });
  byId("clear-filters").addEventListener("click", resetFilters);
  byId("retry").addEventListener("click", load);
  load();
})();
