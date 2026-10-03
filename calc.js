/* ==========================================================================
   Calculator + hidden gesture.
   Gesture:  hold "=" ≥ 2.5 s → release → tap "=" once (within 10 s).
   Nothing on screen hints at it. Any other key cancels the sequence.
   ========================================================================== */
(() => {
  'use strict';
  const HOLD_MS = 2500, ARM_WINDOW_MS = 10000, TAP_MAX_MS = 900;
  const OPS = '+−×÷';
  const $ = (s) => document.querySelector(s);
  const exprEl = $('#expr'), outEl = $('#out'), eqBtn = $('#eq');

  let expr = '';          // e.g. "12+3×4"
  let result = null;      // string after "=" was pressed
  let armedUntil = 0;

  const vaultOpen = () => !!(window.PCVault && window.PCVault.isOpen());
  const disarm = () => { armedUntil = 0; };

  /* ----------------------------------------------------------- evaluation -- */
  function evaluate(src) {
    // Recursive-descent parser: no eval(). Grammar:
    //  sum := prod (('+'|'−') prod)* ; prod := un (('×'|'÷') un)* ;
    //  un  := '−' un | num ('%')*
    let i = 0;
    const peek = () => src[i];
    function num() {
      let j = i;
      while (/[0-9.]/.test(src[i] || '')) i++;
      const s = src.slice(j, i);
      if (!s || s === '.') throw new Error('syntax');
      let v = parseFloat(s);
      while (peek() === '%') { v /= 100; i++; }
      return v;
    }
    function un() { if (peek() === '−') { i++; return -un(); } return num(); }
    function prod() {
      let v = un();
      while (peek() === '×' || peek() === '÷') {
        const o = src[i++]; const r = un();
        if (o === '÷' && r === 0) throw new Error('div0');
        v = o === '×' ? v * r : v / r;
      }
      return v;
    }
    function sum() {
      let v = prod();
      while (peek() === '+' || peek() === '−') { const o = src[i++]; const r = prod(); v = o === '+' ? v + r : v - r; }
      return v;
    }
    const v = sum();
    if (i < src.length) throw new Error('syntax');
    return v;
  }
  const fmt = (n) => {
    if (!isFinite(n)) throw new Error('range');
    let s = parseFloat(n.toPrecision(12)).toString();
    if (s.includes('e')) s = n.toExponential(6).replace(/\.?0+e/, 'e');
    return s.replace('-', '−');
  };

  /* -------------------------------------------------------------- display -- */
  function render() {
    const shown = result !== null ? result : (expr || '0');
    outEl.textContent = result !== null ? result : lastNumber() || '0';
    exprEl.textContent = result !== null ? expr + ' =' : (expr && /[+−×÷]/.test(expr.slice(1)) ? expr : '');
    const len = outEl.textContent.length;
    outEl.className = 'out' + (len > 14 ? ' xs' : len > 11 ? ' s' : len > 8 ? ' m' : '');
    void shown;
  }
  function lastNumber() {
    const m = expr.match(/(−?[0-9.]*%*)$/);
    return m && m[1] && m[1] !== '−' ? m[1] : (expr || '');
  }

  /* ---------------------------------------------------------------- input -- */
  function press(k) {
    disarm();
    if (k === 'AC') { expr = ''; result = null; return render(); }
    if (result !== null) {
      // continue from result with an operator, otherwise start fresh
      if (OPS.includes(k) || k === '%') { expr = result === 'Error' ? '' : result; }
      else if (k !== 'BS' && k !== '±') { expr = ''; }
      else if (k === 'BS') { expr = ''; }
      else { expr = result === 'Error' ? '' : result; }
      result = null;
      if (k === 'BS') return render();
    }
    if (/[0-9]/.test(k)) {
      const m = expr.match(/([0-9.]*)%*$/);
      const cur = m ? m[1] : '';
      if (expr.endsWith('%')) return render();
      if (cur === '0' && k === '0') return render();
      if (cur === '0') expr = expr.slice(0, -1);
      if (cur.replace('.', '').length >= 15) return render();
      expr += k;
    } else if (k === '.') {
      const m = expr.match(/([0-9.]*)%*$/);
      if (expr.endsWith('%')) return render();
      if (m && m[1].includes('.')) return render();
      if (!m || m[1] === '') expr += '0';
      expr += '.';
    } else if (OPS.includes(k)) {
      if (!expr) { if (k === '−') expr = '−'; return render(); }
      if (expr === '−') return render();
      const last = expr.slice(-1);
      if (OPS.includes(last)) {
        if (k === '−' && '×÷'.includes(last)) expr += k;
        else expr = expr.replace(/[+−×÷]+$/, '') + k;
      } else expr += k;
    } else if (k === '%') {
      if (/[0-9.]$/.test(expr) || expr.endsWith('%')) expr += '%';
    } else if (k === 'BS') {
      expr = expr.slice(0, -1);
    } else if (k === '±') {
      const m = expr.match(/(^|[+×÷−])(−?)([0-9]*\.?[0-9]*%*)$/);
      if (m && m[3]) {
        const head = expr.slice(0, expr.length - m[0].length);
        expr = head + m[1] + (m[2] ? '' : '−') + m[3];
      } else if (!expr) expr = '−';
    }
    render();
  }

  function equals() {
    if (!expr) return;
    let src = expr.replace(/[+−×÷]+$/, '');
    if (!src) return;
    try { result = fmt(evaluate(src)); expr = src; }
    catch (e) { result = 'Error'; }
    render();
  }

  function reset() { expr = ''; result = null; disarm(); render(); }

  /* ------------------------------------------------- "=" key + gesture ----- */
  function onEqualsReleased(heldMs) {
    const now = Date.now();
    if (armedUntil > now && heldMs < TAP_MAX_MS) {     // the single confirming tap
      disarm();
      if (window.PCVault) window.PCVault.open();
      return;
    }
    disarm();
    if (heldMs >= HOLD_MS) armedUntil = now + ARM_WINDOW_MS;   // long hold arms silently
    equals();                                                   // looks like a normal "="
  }

  let downAt = 0;
  eqBtn.addEventListener('contextmenu', (e) => e.preventDefault());
  eqBtn.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    downAt = performance.now();
    eqBtn.classList.add('down');
    try { eqBtn.setPointerCapture(e.pointerId); } catch (_) {}
  });
  eqBtn.addEventListener('pointerup', () => {
    eqBtn.classList.remove('down');
    if (!downAt) return;
    const held = performance.now() - downAt; downAt = 0;
    onEqualsReleased(held);
  });
  const cancelEq = () => { downAt = 0; eqBtn.classList.remove('down'); };
  eqBtn.addEventListener('pointercancel', cancelEq);
  eqBtn.addEventListener('lostpointercapture', () => eqBtn.classList.remove('down'));

  /* --------------------------------------------------------- other keys ---- */
  $('#keys').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-k]');
    if (b) press(b.dataset.k);
  });
  $('#keys').addEventListener('contextmenu', (e) => e.preventDefault());

  /* ------------------------------------------------------------ keyboard --- */
  let kDown = 0;
  const isEq = (e) => e.key === '=' || e.key === 'Enter';
  window.addEventListener('keydown', (e) => {
    if (vaultOpen() || e.ctrlKey || e.metaKey || e.altKey) return;
    if (isEq(e)) { e.preventDefault(); if (!e.repeat && !kDown) kDown = performance.now(); eqBtn.classList.add('down'); return; }
    const map = { '*': '×', 'x': '×', 'X': '×', '/': '÷', '-': '−', '+': '+', '.': '.', ',': '.', '%': '%', 'Backspace': 'BS', 'Escape': 'AC', 'Delete': 'AC' };
    const k = /^[0-9]$/.test(e.key) ? e.key : map[e.key];
    if (k) { e.preventDefault(); press(k); }
  });
  window.addEventListener('keyup', (e) => {
    if (vaultOpen() || !isEq(e)) return;
    eqBtn.classList.remove('down');
    if (!kDown) return;
    const held = performance.now() - kDown; kDown = 0;
    onEqualsReleased(held);
  });
  window.addEventListener('blur', () => { kDown = 0; });

  window.PCCalc = { reset };
  render();
})();
