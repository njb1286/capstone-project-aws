import{g as d,h as r,i,f}from"./index-a953373a.js";import{u as g}from"./useUploadForm-eb2ae9ff.js";import"./Form-f058ec6f.js";import"./index-3059fd31.js";import"./FormCheckInput-ed07f4c3.js";import"./DropDown-12885d08.js";import"./useWindow-d8bccd82.js";import"./Button-ef43203b.js";import"./ButtonGroup-b020ac75.js";const l=async t=>{const a=await fetch(`${r}/get?id=${t}`,i("GET"));return a.status>=299?null:await a.json()},I=async()=>{const t=await fetch(`${r}/last`,i("GET"));return t.status>=299?null:await t.json()},y=()=>{const t=d();return async e=>{if(e){const o=await l(e);if(!o)return;t({type:"ADD_IMAGE_ITEM",payload:o})}const n=await I();n&&t({type:"ADD_IMAGE_ITEM",payload:n})}};function $(){const t=f(),a=y();async function e(p,m,c,u){const s=new FormData;if(s.append("image",c),s.append("title",p),s.append("description",m),s.append("category",u),(await fetch(`${r}/form`,{body:s,...i("POST")})).status>299){o();return}a(),t("/")}const[n,o]=g({updating:!1,onSubmit:e});return n}export{$ as default};
