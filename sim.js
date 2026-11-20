/* DDoS シミュレーター
   やっていること: 1 秒刻みの数値モデルを回して、グラフと表に描くだけ。
   ネットワークへは一切出ない（CSP の connect-src 'none' で強制）。
   入力はすべてスライダーで、宛先 URL を受け取る口は無い。 */
'use strict';

(() => {
  const T = 120;                 // 計算する秒数
  const STEADY = 30;             // 定常とみなす末尾の秒数
  const BASE_LATENCY = 38;       // 負荷が無いときの応答時間（ms）
  const LEGIT_RPS = 200;         // 正常な利用者のトラフィック（毎秒・固定）
  const HEADER_BYTES = 620;      // ヘッダ・TLS などの概算

  /* ---------------- スライダー定義 ---------------- */

  const int = (v) => v.toLocaleString('ja-JP');

  const SPEC = {
    botsRange: {
      min: 10, max: 200000, log: true, out: 'botsVal',
      fmt: (v) => int(v) + ' 台',
    },
    rateRange: {
      min: 1, max: 200, log: true, out: 'rateVal',
      fmt: (v) => int(v) + ' req/s',
    },
    sizeRange: {
      min: 100, max: 4000, log: false, direct: true, step: 100, out: 'sizeVal',
      fmt: (v) => int(v) + ' B',
    },
    rampRange: {
      min: 0, max: 60, log: false, direct: true, step: 1, out: 'rampVal',
      fmt: (v) => (v === 0 ? '即時' : int(v) + ' 秒'),
    },
    capRange: {
      min: 50, max: 100000, log: true, out: 'capVal',
      fmt: (v) => int(v) + ' req/s',
    },
    linkRange: {
      min: 10, max: 100000, log: true, out: 'linkVal',
      fmt: (v) => (v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 0 : 1) + ' Gbps' : int(v) + ' Mbps'),
    },
    ipLimitRange: {
      min: 0, max: 200, log: false, direct: true, step: 5, out: 'ipLimitVal',
      fmt: (v) => (v === 0 ? 'なし' : int(v) + ' req/s/IP'),
    },
    scrubRange: {
      min: 0, max: 99, log: false, direct: true, step: 1, out: 'scrubVal',
      fmt: (v) => (v === 0 ? 'なし' : int(v) + ' %'),
    },
    nodesRange: {
      min: 1, max: 64, log: false, direct: true, step: 1, out: 'nodesVal',
      fmt: (v) => (v === 1 ? '1（分散なし）' : int(v) + ' 拠点'),
    },
  };

  const PRESETS = {
    small: { botsRange: 1000, rateRange: 3, sizeRange: 800, rampRange: 10, capRange: 5000, linkRange: 1000, ipLimitRange: 0, scrubRange: 0, nodesRange: 1 },
    mid: { botsRange: 10000, rateRange: 10, sizeRange: 900, rampRange: 15, capRange: 5000, linkRange: 1000, ipLimitRange: 0, scrubRange: 0, nodesRange: 1 },
    large: { botsRange: 100000, rateRange: 20, sizeRange: 900, rampRange: 20, capRange: 5000, linkRange: 1000, ipLimitRange: 0, scrubRange: 0, nodesRange: 1 },
    defended: { botsRange: 100000, rateRange: 20, sizeRange: 900, rampRange: 20, capRange: 5000, linkRange: 5000, ipLimitRange: 15, scrubRange: 98, nodesRange: 12 },
  };

  /* ---------------- スライダーの値 <-> 位置 ---------------- */

  // 対数スライダーは位置（0..1000）から値を出し、桁に合わせて丸める。
  // 例: 99,950 ではなく 100,000 と表示させ、操作の意味を読み取りやすくする。
  function niceRound(v) {
    if (!isFinite(v) || v <= 0) return 0;
    const mag = Math.pow(10, Math.max(0, Math.floor(Math.log10(v)) - 1));
    return Math.round(v / mag) * mag;
  }

  function valueOf(id) {
    const el = document.getElementById(id);
    const sp = SPEC[id];
    if (sp.direct) return Number(el.value);
    const pos = Number(el.value) / 1000;
    const v = Math.exp(Math.log(sp.min) + (Math.log(sp.max) - Math.log(sp.min)) * pos);
    return Math.min(sp.max, Math.max(sp.min, niceRound(v)));
  }

  function setValue(id, value) {
    const el = document.getElementById(id);
    const sp = SPEC[id];
    const v = Math.min(sp.max, Math.max(sp.min, value));
    if (sp.direct) {
      el.value = String(Math.round(v / (sp.step || 1)) * (sp.step || 1));
      return;
    }
    const pos = (Math.log(v) - Math.log(sp.min)) / (Math.log(sp.max) - Math.log(sp.min));
    el.value = String(Math.round(Math.min(1, Math.max(0, pos)) * 1000));
  }

  /* ---------------- 乱数（毎回同じ結果にするため固定シード） ---------------- */

  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6D2B79F5) >>> 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  /* ---------------- モデル ---------------- */

  function simulate(p) {
    const rand = mulberry32(0x5eed);
    const nodes = p.nodes;
    const capacity = p.cap * nodes;
    const effBytes = p.size + HEADER_BYTES;
    const linkRpsPerNode = (p.link * 1e6) / 8 / effBytes;
    const linkRps = linkRpsPerNode * nodes;

    const rows = [];
    for (let t = 0; t < T; t += 1) {
      const ramp = p.ramp > 0 ? Math.min(1, (t + 1) / p.ramp) : 1;
      const bots = p.bots * ramp;

      const raw = bots * p.rate;
      const perBot = p.ipLimit > 0 ? Math.min(p.rate, p.ipLimit) : p.rate;
      const afterLimit = bots * perBot;
      const afterScrub = afterLimit * (1 - p.scrub / 100);

      // 攻撃トラフィックが回線を通れる量
      const incoming = Math.min(afterScrub, linkRps);
      // 正常な利用者の分を足したものが、サーバーに並ぶ総量
      const arrival = incoming + LEGIT_RPS;
      const served = Math.min(arrival, capacity);
      const util = capacity > 0 ? arrival / capacity : 0;

      // 応答時間: 利用率が 0.7 を超えたあたりから急に伸びる
      let p50;
      if (util <= 0.7) {
        p50 = BASE_LATENCY * (1 + 0.4 * (util / 0.7));
      } else {
        const x = Math.min(1, (util - 0.7) / 0.3);
        p50 = BASE_LATENCY * (1.4 + 28 * Math.pow(x, 1.6));
      }
      const p95 = p50 * 2.6;

      // 可用性: 溢れた分は比例して落ちる + 待ち行列満杯時のタイムアウト
      // 可用性 = 正常な利用者のリクエストが通る割合。
      // 攻撃トラフィックが上流で捨てられる分は、可用性を下げない。
      const falsePositive = p.scrub > 0 ? 0.005 : 0;
      let avail = 1 - falsePositive;
      if (arrival > capacity) {
        // 溢れたら、並んでいる総量に比例して落ちる（攻撃も利用者も同じ列に並ぶ）
        avail *= capacity / arrival;
      } else if (util > 0.85) {
        avail *= 1 - 0.15 * ((util - 0.85) / 0.15);
      }
      avail = Math.max(0, Math.min(1, avail)) * (0.9995 + rand() * 0.0005);

      rows.push({ t, raw, afterLimit, afterScrub, incoming, arrival, served, util, p50, p95, avail });
    }

    const steady = rows.slice(T - STEADY);
    const peak = (key) => steady.reduce((m, r) => Math.max(m, r[key]), 0);
    const totalIn = steady.reduce((s, r) => s + r.arrival, 0);
    const totalOut = steady.reduce((s, r) => s + r.served, 0);

    const summary = {
      rows,
      capacity,
      linkRps,
      nodes,
      rawPeak: peak('raw'),
      limitPeak: peak('afterLimit'),
      scrubPeak: peak('afterScrub'),
      inPeak: peak('arrival'),
      servedPeak: peak('served'),
      utilPeak: peak('util'),
      p95Peak: peak('p95'),
      availAvg: steady.reduce((s, r) => s + r.avail, 0) / STEADY,
      dropRate: totalIn > 0 ? 1 - totalOut / totalIn : 0,
      headroom: capacity - peak('arrival'),
      firstFail: rows.findIndex((r) => r.avail < 0.9),
      // どこで最初に詰まっているか（定常時の最大値どうしを比較）
      bottleneck: (() => {
        const linkBound = linkRps < peak('afterScrub') * 0.99;
        const capBound = capacity < peak('arrival') * 0.99;
        if (linkBound && capBound) return 'both';
        if (capBound) return 'capacity';
        if (linkBound) return 'link';
        return 'none';
      })(),
    };
    return summary;
  }

  /* ---------------- 表示 ---------------- */

  const fmtRate = (n) => {
    if (!isFinite(n) || n <= 0) return '0';
    if (n >= 1e8) return (n / 1e8).toFixed(2) + ' 億';
    if (n >= 1e4) return (n / 1e4).toFixed(n >= 1e5 ? 1 : 2) + ' 万';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + ' 千';
    return String(Math.round(n));
  };

  // 目盛り用: 桁が飛んでも読みやすいよう、万・億は整数で表す
  const fmtAxis = (n) => {
    if (n >= 1e8) return Math.round(n / 1e8) + ' 億';
    if (n >= 1e4) return Math.round(n / 1e4) + ' 万';
    if (n >= 1e3) return Math.round(n / 1e3) + ' 千';
    return String(Math.round(n));
  };

  // 線が重なっても読めるよう、下に白い縁を敷いてから本線を描く
  function lineHalo(ctx, pts, color, width) {
    line(ctx, pts, '#ffffff', width + 4);
    line(ctx, pts, color, width);
  }

  const fmtPct = (x, digits = 1) => (x * 100).toFixed(digits) + ' %';
  const fmtMs = (n) => (n >= 1000 ? (n / 1000).toFixed(2) + ' 秒' : Math.round(n) + ' ms');

  const $ = (id) => document.getElementById(id);

  function paintStats(s) {
    $('rawView').textContent = fmtRate(s.rawPeak) + ' rps';
    $('inView').textContent = fmtRate(s.inPeak) + ' rps';
    $('servedView').textContent = fmtRate(s.servedPeak) + ' rps';
    $('dropView').textContent = fmtPct(s.dropRate, s.dropRate >= 0.999 ? 2 : 1);
    $('availView').textContent = fmtPct(s.availAvg, 2);
    $('p95View').textContent = fmtMs(s.p95Peak);

    $('statDrop').className = 'stat ' + (s.dropRate > 0.1 ? 'is-bad' : 'is-ok');
    $('statAvail').className = 'stat ' + (s.availAvg < 0.9 ? 'is-bad' : 'is-ok');
    $('statP95').className = 'stat ' + (s.p95Peak > 500 ? 'is-bad' : s.p95Peak > 150 ? '' : 'is-ok');
  }

  function paintVerdict(s) {
    const box = $('verdict');
    const title = $('verdictTitle');
    const body = $('verdictBody');
    let kind;
    let text;
    let note;

    const where = {
      both: '回線と処理能力の両方が上限',
      capacity: '処理能力が上限',
      link: '回線帯域が上限',
      none: '上限に達していない',
    }[s.bottleneck];

    if (s.availAvg >= 0.97) {
      kind = 'ok';
      text = '耐えています';
      note = '定常時の可用性は ' + fmtPct(s.availAvg, 2) + '。処理能力に ' +
        fmtRate(s.headroom) + ' req/s の余力が残っています（' + where + '）。';
    } else if (s.availAvg >= 0.6) {
      kind = 'warn';
      text = '一部で取りこぼし';
      note = '可用性 ' + fmtPct(s.availAvg, 2) + '、p95 は ' + fmtMs(s.p95Peak) +
        '。応答は返るが、遅い・失敗する利用者が出ます（' + where + '）。';
    } else {
      kind = 'bad';
      text = '崩壊しています';
      note = '可用性 ' + fmtPct(s.availAvg, 2) + '、未処理 ' + fmtPct(s.dropRate, 1) +
        '。攻撃の ' + fmtPct(s.inPeak / (s.rawPeak || 1), 1) + ' が届き、そのうち ' +
        fmtPct(s.servedPeak / (s.inPeak || 1), 1) + ' しか処理できていません（' + where + '）。';
    }
    box.className = 'verdict ' + kind;
    title.textContent = text;
    body.textContent = note;
  }

  function paintFunnel(s) {
    const head = s.rawPeak > 0 ? s.rawPeak : 1;
    // 最後の 1 行は「能力」であって流量の段階ではないので割合は出さない
    const rows = [
      ['攻撃の総量', s.rawPeak, true],
      ['IP レート制限の後', s.limitPeak, true],
      ['スクラビングの後', s.scrubPeak, true],
      ['回線上限の後（＝サーバーに届いた量）', s.inPeak, true],
      ['サーバーが処理した量', s.servedPeak, true],
      ['処理能力（拠点合計）', s.capacity, false],
    ];
    const body = $('funnelBody');
    body.textContent = '';
    rows.forEach(([label, value, showPct]) => {
      const tr = document.createElement('tr');

      const th = document.createElement('th');
      th.textContent = label;

      const tdV = document.createElement('td');
      tdV.className = 'num';
      tdV.textContent = fmtRate(value) + ' rps';

      const tdP = document.createElement('td');
      tdP.className = 'num';
      tdP.textContent = showPct
        ? (value / head * 100).toFixed(value / head >= 10 ? 0 : 1) + ' %'
        : '—';

      tr.append(th, tdV, tdP);
      body.append(tr);
    });
  }

  /* ---------------- グラフ ---------------- */

  const COL = {
    raw: '#b3261e',
    incoming: '#d98a2b',
    served: '#1d7a4c',
    cap: '#00427a',
    p95: '#005bbc',
    grid: '#e6ebf1',
    axis: '#8a97a5',
  };

  let labelPx = 11;   // 狭い画面では少し大きくして読みやすくする

  function setup(cv) {
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth || 600;
    const h = cv.clientHeight || 220;
    cv.width = Math.round(w * dpr);
    cv.height = Math.round(h * dpr);
    const ctx = cv.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    labelPx = w < 480 ? 12 : 11;
    ctx.font = labelPx + 'px system-ui, -apple-system, "Segoe UI", sans-serif';
    ctx.textBaseline = 'middle';
    return { ctx, w, h };
  }

  function line(ctx, pts, color, width, dash) {
    ctx.save();
    ctx.strokeStyle = color;
    ctx.lineWidth = width;
    ctx.lineJoin = 'round';
    if (dash) ctx.setLineDash(dash);
    ctx.beginPath();
    pts.forEach((pt, i) => (i ? ctx.lineTo(pt[0], pt[1]) : ctx.moveTo(pt[0], pt[1])));
    ctx.stroke();
    ctx.restore();
  }

  function axisTitle(ctx, text, x, y, align) {
    ctx.save();
    ctx.fillStyle = COL.axis;
    ctx.font = (labelPx - 1) + 'px system-ui, -apple-system, "Segoe UI", sans-serif';
    ctx.textAlign = align;
    ctx.fillText(text, x, y);
    ctx.restore();
  }

  function drawFlow(s) {
    const { ctx, w, h } = setup($('flowChart'));
    const pad = { l: 62, r: 22, t: 26, b: 26 };
    const innerW = w - pad.l - pad.r;
    const innerH = h - pad.t - pad.b;

    const maxV = Math.max(10, s.rawPeak, s.capacity);
    const hi = Math.ceil(Math.log10(maxV));
    const lo = 0;

    const yLog = (v) => pad.t + (1 - (Math.log10(Math.max(v, 1)) - lo) / (hi - lo)) * innerH;
    const xOf = (i) => pad.l + (i / (T - 1)) * innerW;

    // 処理能力の帯（線が重なっても天井が読めるように面で示す）
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(pad.l, h - pad.b);
    ctx.lineTo(pad.l, yLog(s.capacity));
    ctx.lineTo(w - pad.r, yLog(s.capacity));
    ctx.lineTo(w - pad.r, h - pad.b);
    ctx.closePath();
    ctx.fillStyle = 'rgba(0, 66, 122, .07)';
    ctx.fill();
    ctx.restore();

    // 目盛り（10 の累乗）
    ctx.strokeStyle = COL.grid;
    ctx.lineWidth = 1;
    ctx.fillStyle = COL.axis;
    ctx.textAlign = 'right';
    for (let e = lo; e <= hi; e += 1) {
      const y = yLog(Math.pow(10, e));
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(w - pad.r, y);
      ctx.stroke();
      ctx.fillText(fmtAxis(Math.pow(10, e)), pad.l - 8, y);
    }

    // 横軸（0 / 60 / 120 秒）
    [0, 60, 120].forEach((sec) => {
      const x = pad.l + (sec / T) * innerW;
      ctx.beginPath();
      ctx.moveTo(x, pad.t);
      ctx.lineTo(x, h - pad.b);
      ctx.stroke();
      ctx.textAlign = sec === 0 ? 'left' : sec === T ? 'right' : 'center';
      ctx.fillText(sec + ' 秒', x, h - pad.b + 12);
    });

    axisTitle(ctx, 'req/s（対数目盛）', pad.l, pad.t - 13, 'left');

    // 3 本の線。色に頼りすぎないよう、線種も変える
    // 能力の天井は帯の上端で示す（線だと処理量と重なって読めなくなる）
    ctx.save();
    ctx.strokeStyle = 'rgba(0, 66, 122, .40)';
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    ctx.moveTo(pad.l, yLog(s.capacity));
    ctx.lineTo(w - pad.r, yLog(s.capacity));
    ctx.stroke();

    // 天井の値をその場に書く（表を照合しなくても読めるように）
    const capText = '処理能力 ' + fmtRate(s.capacity) + ' req/s';
    ctx.font = (labelPx - 1) + 'px system-ui, -apple-system, "Segoe UI", sans-serif';
    ctx.textAlign = 'right';
    ctx.lineWidth = 3;
    ctx.strokeStyle = 'rgba(255, 255, 255, .95)';
    ctx.strokeText(capText, w - pad.r - 4, yLog(s.capacity) - 9);
    ctx.fillStyle = COL.cap;
    ctx.fillText(capText, w - pad.r - 4, yLog(s.capacity) - 9);
    ctx.restore();

    const series = [
      [s.rows.map((r, i) => [xOf(i), yLog(r.raw)]), COL.raw, 1.5, [9, 4]],
      [s.rows.map((r, i) => [xOf(i), yLog(r.arrival)]), COL.incoming, 1.8, [3, 3]],
      [s.rows.map((r, i) => [xOf(i), yLog(r.served)]), COL.served, 2.6, null],
    ];
    series.forEach(([pts, color, width, dash]) => {
      line(ctx, pts, color, width, dash);
      // 終端の点。データが 120 秒で終わっていることを示す
      const last = pts[pts.length - 1];
      ctx.save();
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(last[0], last[1], 2.6, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    });
  }

  function drawQual(s) {
    const { ctx, w, h } = setup($('qualChart'));
    const pad = { l: 48, r: 74, t: 26, b: 26 };
    const innerW = w - pad.l - pad.r;
    const innerH = h - pad.t - pad.b;

    const p95Max = Math.max(200, Math.ceil(s.p95Peak / 200) * 200);
    const yAvail = (a) => pad.t + (1 - a) * innerH;
    const yP95 = (v) => pad.t + (1 - v / p95Max) * innerH;
    const xOf = (i) => pad.l + (i / (T - 1)) * innerW;

    // 目盛り
    ctx.strokeStyle = COL.grid;
    ctx.lineWidth = 1;
    ctx.fillStyle = COL.axis;
    ctx.textAlign = 'right';
    [0, 0.5, 1].forEach((a) => {
      const y = yAvail(a);
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(w - pad.r, y);
      ctx.stroke();
      ctx.fillText(Math.round(a * 100) + ' %', pad.l - 6, y);
    });
    ctx.textAlign = 'left';
    [0, 0.5, 1].forEach((f) => {
      const v = p95Max * f;
      ctx.fillText(Math.round(v) + ' ms', w - pad.r + 8, yP95(v));
    });

    [0, 60, 120].forEach((sec) => {
      const x = pad.l + (sec / T) * innerW;
      ctx.beginPath();
      ctx.moveTo(x, pad.t);
      ctx.lineTo(x, h - pad.b);
      ctx.stroke();
      ctx.textAlign = sec === 0 ? 'left' : sec === T ? 'right' : 'center';
      ctx.fillText(sec + ' 秒', x, h - pad.b + 12);
    });

    axisTitle(ctx, '可用性 %', pad.l - 6, pad.t - 12, 'right');
    axisTitle(ctx, 'p95 応答時間', w - pad.r + 14, pad.t - 12, 'left');

    // 可用性（面）
    const availPts = s.rows.map((r, i) => [xOf(i), yAvail(r.avail)]);
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(availPts[0][0], h - pad.b);
    availPts.forEach((pt) => ctx.lineTo(pt[0], pt[1]));
    ctx.lineTo(availPts[availPts.length - 1][0], h - pad.b);
    ctx.closePath();
    ctx.fillStyle = 'rgba(29, 122, 76, .18)';
    ctx.fill();
    ctx.restore();
    line(ctx, availPts, COL.served, 2);

    // 90 % のしきい線
    line(ctx, [[pad.l, yAvail(0.9)], [w - pad.r, yAvail(0.9)]], COL.raw, 1.2, [5, 4]);

    // p95（右軸）
    line(ctx, s.rows.map((r, i) => [xOf(i), yP95(Math.min(r.p95, p95Max))]), COL.p95, 1.8);
  }

  /* ---------------- 起動 ---------------- */

  function render() {
    Object.keys(SPEC).forEach((id) => {
      $(SPEC[id].out).textContent = SPEC[id].fmt(valueOf(id));
    });

    const params = {
      bots: valueOf('botsRange'),
      rate: valueOf('rateRange'),
      size: valueOf('sizeRange'),
      ramp: valueOf('rampRange'),
      cap: valueOf('capRange'),
      link: valueOf('linkRange'),
      ipLimit: valueOf('ipLimitRange'),
      scrub: valueOf('scrubRange'),
      nodes: valueOf('nodesRange'),
    };

    const summary = simulate(params);
    paintStats(summary);
    paintVerdict(summary);
    paintFunnel(summary);
    drawFlow(summary);
    drawQual(summary);
  }

  function applyPreset(name) {
    const preset = PRESETS[name];
    if (!preset) return;
    Object.keys(preset).forEach((id) => setValue(id, preset[id]));
    render();
  }

  function init() {
    Object.keys(SPEC).forEach((id) => {
      const el = $(id);
      const sp = SPEC[id];
      if (sp.direct) {
        el.min = String(sp.min);
        el.max = String(sp.max);
        el.step = String(sp.step || 1);
      } else {
        el.min = '0';
        el.max = '1000';
        el.step = '1';
      }
      el.addEventListener('input', render);
    });

    document.querySelectorAll('[data-preset]').forEach((btn) => {
      btn.addEventListener('click', () => applyPreset(btn.dataset.preset));
    });

    setValue('botsRange', 100000);
    setValue('rateRange', 20);
    setValue('sizeRange', 900);
    setValue('rampRange', 20);
    setValue('capRange', 5000);
    setValue('linkRange', 1000);
    setValue('ipLimitRange', 0);
    setValue('scrubRange', 0);
    setValue('nodesRange', 1);

    render();

    let timer = 0;
    window.addEventListener('resize', () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(render, 120);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
