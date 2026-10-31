window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}
gtag('js',new Date());gtag('config','G-NH3J6P25ZN');
document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a');if(!a)return;
var t=(a.textContent||'').trim();
if(/Request a Store Review/i.test(t)){gtag('event','store_review_click',{page:location.pathname});}
else if(/calendly\.com/i.test(a.getAttribute('href')||'')){gtag('event','calendly_click',{page:location.pathname});}
else if(/^mailto:/i.test(a.getAttribute('href')||'')){gtag('event','email_click',{page:location.pathname});}
else if(/wa\.me/i.test(a.getAttribute('href')||'')){gtag('event','whatsapp_click',{page:location.pathname});}
else if(/upwork\.com/i.test(a.getAttribute('href')||'')){gtag('event','upwork_click',{page:location.pathname});}
else if(/consultation/i.test(a.getAttribute('href')||'')){gtag('event','consultation_click',{page:location.pathname});}
},true);

// Calendly booking confirmation (fires when an embed posts it)
window.addEventListener('message',function(e){if(e.origin==='https://calendly.com'&&e.data&&e.data.event==='calendly.event_scheduled'){gtag('event','calendly_booked');}});
