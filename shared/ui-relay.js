// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// General › Your own relay (Mac, Windows, Linux): the address (and key) of a TwinDesk Relay you run
// (relay/twindesk-relay.js, shared/relay.js), so a phone or computer away from this network can
// connect. Empty by default: nothing runs and nothing is sent anywhere until an address is saved.
// Allow pairing through the relay (off by default) shows this computer's TwinDesk ID, which someone
// with the same relay types in Connect by address to ask to pair.
//   const r = UI.relayCard(); page.append(r.el); on each state: r.update(state.net.relay)
'use strict';

(() => {
  const t = (...a) => I18n.t(...a);
  UI.relayCard = function relayCard() {
    const { el } = UI;
    const addr = el('input', { type: 'text', class: 'relay-addr', attrs: { placeholder: 'relay.example.com:47100', spellcheck: 'false', autocomplete: 'off', 'aria-label': t('Relay address') } });
    const key = el('input', { type: 'password', class: 'relay-key', attrs: { placeholder: t('Key (if it has one)'), autocomplete: 'off', 'aria-label': t('Relay key') } });
    let last = {}; // the saved setting, as the last state showed it
    const save = UI.button(t('Save'), () => UI.api.setNet({ relay: { addr: addr.value.trim(), key: key.value, pair: last.pair === true } }), 'small');
    const remove = UI.button(t('Remove'), () => { addr.value = ''; key.value = ''; UI.api.setNet({ relay: { addr: '', key: '', pair: false } }); }, 'small');
    const row = UI.row(t('Relay address'), '', [addr, key, save, remove]);
    const pairSw = UI.switch((v) => UI.api.setNet({ relay: { addr: last.addr || '', key: last.key || '', pair: v } }), { label: t('Allow pairing through the relay') });
    const pairRow = UI.row(t('Allow pairing through the relay'), '', [pairSw]);
    const how = UI.row(t('How it works'), t('Run TwinDesk Relay (relay/twindesk-relay.js in TwinDesk’s source, Node only) on a server both devices can reach, and add its address here. A phone or computer that isn’t on this network then connects through it. The relay only passes on the session, which stays encrypted end to end with this computer’s certificate: it can’t read anything or tell which devices they are.'), []);
    const card = UI.card(t('Your own relay'), [row, pairRow, how]);
    let typed = false;
    addr.oninput = key.oninput = () => { typed = true; };
    return {
      el: card,
      update(r) {
        r = r || {};
        last = r;
        pairRow.hidden = !r.addr;
        pairSw.set(r.pair === true);
        pairRow.setHint(!r.pair ? t('Off: only devices already paired with this computer use the relay')
          : r.code ? t('This computer’s TwinDesk ID: {code}. Someone with the same relay types it in Connect by address; you still compare a code and click Allow.', { code: r.code })
            : t('Connecting to the relay…'));
        if (!typed || document.activeElement !== addr) { addr.value = r.addr || ''; if (!typed) key.value = r.key || ''; }
        remove.hidden = !r.addr;
        const why = r.error ? ` · ${t(r.error)}` : '';
        row.setHint(!r.addr ? t('None: devices connect on this network, the cable, Bluetooth or Tailscale')
          : r.state === 'ready' ? t('Connected to the relay: a phone or computer away from here can reach this computer')
            : r.state === 'connecting' ? t('Connecting to the relay…')
              : t('Can’t reach the relay{why}', { why }));
      },
    };
  };
})();
