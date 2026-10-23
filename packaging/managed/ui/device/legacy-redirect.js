'use strict';
'require view';
'require ui';
return view.extend({
 handleSave:null, handleSaveApply:null, handleReset:null,
 render:function(){
  if (ui.menu && ui.menu.flushCache) ui.menu.flushCache();
  var target=L.url('admin','network','pnw-control')+'#pnw-dns';
  window.location.replace(target);
  return E('p',{},[E('a',{href:target},'正在打开统一 DNS 统计页面…')]);
 }
});
