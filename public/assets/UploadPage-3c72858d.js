import{f as d,g as r,h as i,e as f}from"./index-6c100cd4.js";import{u as g}from"./useUploadForm-54a10e47.js";import"./Form-350b8ed3.js";import"./index-67c4be86.js";import"./FormCheckInput-365b67ca.js";import"./DropDown-0a653e98.js";import"./DataKey-95b4b59e.js";import"./useWindow-90552efc.js";import"./mergeOptionsWithPopperConfig-0fdd69a4.js";import"./Button-0b973d54.js";import"./ButtonGroup-59945e00.js";const l=async t=>{const a=await fetch(`${r}/get?id=${t}`,i("GET"));return a.status>=299?null:await a.json()},I=async()=>{const t=await fetch(`${r}/last`,i("GET"));return t.status>=299?null:await t.json()},y=()=>{const t=d();return async e=>{if(e){const o=await l(e);if(!o)return;t({type:"ADD_IMAGE_ITEM",payload:o})}const n=await I();n&&t({type:"ADD_IMAGE_ITEM",payload:n})}};function U(){const t=f(),a=y();async function e(p,m,c,u){const s=new FormData;if(s.append("image",c),s.append("title",p),s.append("description",m),s.append("category",u),(await fetch(`${r}/form`,{body:s,...i("POST")})).status>299){o();return}a(),t("/")}const[n,o]=g({updating:!1,onSubmit:e});return n}export{U as default};
