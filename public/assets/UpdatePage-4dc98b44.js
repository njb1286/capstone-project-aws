import{e as g,f,i as y,r as I,g as E,h}from"./index-0d223769.js";import{u as M}from"./useUploadForm-ec3a7a3c.js";import{u as P}from"./useGetImageItem-e8e9bb4b.js";import"./Form-c19e284b.js";import"./index-42e6a327.js";import"./FormCheckInput-132a99e2.js";import"./DropDown-db17f0de.js";import"./DataKey-95321642.js";import"./useWindow-88a8cae2.js";import"./mergeOptionsWithPopperConfig-8e92920a.js";import"./Button-34612679.js";import"./ButtonGroup-4ce05ae6.js";function x(){const p=g(),n=f(),t=new URLSearchParams(location.search).get("id"),r=y(o=>t?o.imageItems.find(i=>i.id===+t):void 0),e=P(t),[d,m,c]=M({id:+t,onSubmit:u,updating:!0,title:e.type==="IMAGE_ITEM"?e.payload.title:"",description:e.type==="IMAGE_ITEM"?e.payload.description:"",category:e.type==="IMAGE_ITEM"?e.payload.category:"Other"});if(I.useEffect(()=>{r&&c(r.title,r.description,r.category)},[r]),e.type==="COMPONENT")return e.payload;async function u(o,i,l,s){const a=new FormData;if(a.append("image",l),a.append("title",o),a.append("description",i),a.append("id",t),a.append("category",s),(await fetch(`${E}/update?id=${t}`,{body:a,...h("POST")})).status>299){m();return}n({type:"UPDATE_IMAGE_ITEM",payload:{id:+t,title:o,description:i,category:s}}),p(`/views?id=${t}`)}return d}export{x as default};
