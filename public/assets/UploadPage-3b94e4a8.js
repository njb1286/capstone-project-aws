import{g as d,h as r,i,f}from"./index-5f75a154.js";import{u as g}from"./useUploadForm-7e9aee05.js";import"./Form-c33f40e4.js";import"./index-520c09bc.js";import"./FormCheckInput-291adace.js";import"./DropDown-f251c182.js";import"./useWindow-dbd8ed5a.js";import"./Button-1ddd24fe.js";import"./ButtonGroup-f3c33077.js";const l=async t=>{const a=await fetch(`${r}/get?id=${t}`,i("GET"));return a.status>=299?null:await a.json()},I=async()=>{const t=await fetch(`${r}/last`,i("GET"));return t.status>=299?null:await t.json()},y=()=>{const t=d();return async e=>{if(e){const o=await l(e);if(!o)return;t({type:"ADD_IMAGE_ITEM",payload:o})}const n=await I();n&&t({type:"ADD_IMAGE_ITEM",payload:n})}};function $(){const t=f(),a=y();async function e(p,m,c,u){const s=new FormData;if(s.append("image",c),s.append("title",p),s.append("description",m),s.append("category",u),(await fetch(`${r}/form`,{body:s,...i("POST")})).status>299){o();return}a(),t("/")}const[n,o]=g({updating:!1,onSubmit:e});return n}export{$ as default};
