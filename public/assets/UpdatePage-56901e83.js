import{e as g,f,i as y,r as I,g as E,h}from"./index-a92a2e79.js";import{u as M}from"./useUploadForm-d3de4c5b.js";import{u as P}from"./useGetImageItem-f6998410.js";import"./Form-ecf1671b.js";import"./index-28b5e842.js";import"./FormCheckInput-05a6970d.js";import"./DropDown-8f4dec7b.js";import"./DataKey-852cb963.js";import"./useWindow-ee83e482.js";import"./mergeOptionsWithPopperConfig-b756c39e.js";import"./Button-58481d39.js";import"./ButtonGroup-c76536f8.js";import"./PageNotFound-2811cb32.js";import"./index-02c45f2e.js";function R(){const p=g(),n=f(),t=new URLSearchParams(location.search).get("id"),r=y(o=>t?o.imageItems.find(i=>i.id===+t):void 0),e=P(t),[m,d,c]=M({id:+t,onSubmit:u,updating:!0,title:e.type==="IMAGE_ITEM"?e.payload.title:"",description:e.type==="IMAGE_ITEM"?e.payload.description:"",category:e.type==="IMAGE_ITEM"?e.payload.category:"Other"});if(I.useEffect(()=>{r&&c(r.title,r.description,r.category)},[r]),e.type==="COMPONENT")return e.payload;async function u(o,i,l,s){const a=new FormData;if(a.append("image",l),a.append("title",o),a.append("description",i),a.append("id",t),a.append("category",s),(await fetch(`${E}/update?id=${t}`,{body:a,...h("POST")})).status>299){d();return}n({type:"UPDATE_IMAGE_ITEM",payload:{id:+t,title:o,description:i,category:s}}),p(`/views?id=${t}`)}return m}export{R as default};
