(function(){
  function nav(){return document.querySelector('nav.nav');}
  function set(o){var n=nav();if(!n)return;n.classList.toggle('cm-open',o);var b=n.querySelector('.cm-burger');if(b)b.setAttribute('aria-expanded',o?'true':'false');}
  function ensure(){
    var n=nav();
    if(!n||n.querySelector('.cm-burger'))return;
    var b=document.createElement('button');
    b.type='button';b.className='cm-burger';
    b.setAttribute('aria-label','Menu');b.setAttribute('aria-expanded','false');
    b.innerHTML='<span></span><span></span><span></span>';
    var cta=n.querySelector('a.btn');
    n.insertBefore(b,cta?cta.nextSibling:null);
  }
  document.addEventListener('click',function(e){
    var t=e.target;if(!t||!t.closest)return;
    var n=nav();if(!n)return;
    if(t.closest('.cm-burger')){set(!n.classList.contains('cm-open'));}
    else if(t.closest('nav.nav a')){set(false);}
    else if(!t.closest('nav.nav')){set(false);}
  });
  document.addEventListener('keydown',function(e){if(e.key==='Escape')set(false);});
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',ensure);else ensure();
  window.addEventListener('load',ensure);
  new MutationObserver(ensure).observe(document.documentElement,{childList:true,subtree:true});
})();
