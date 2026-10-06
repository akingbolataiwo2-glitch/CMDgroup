window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}
gtag('js',new Date());gtag('config','G-NH3J6P25ZN');
document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a');if(!a)return;
var t=(a.textContent||'').trim();
if(/Request a Store Review/i.test(t)){gtag('event','store_review_click',{page:location.pathname});}
else if(/consultation/i.test(a.getAttribute('href')||'')){gtag('event','consultation_click',{page:location.pathname});}
},true);
