import{r as s,u as $,j as t,c as M,N as K,k as Q,S as X,l as A,g as G,i as I,f as Y,L as Z}from"./index-0d223769.js";import{u as ee}from"./useLazyImage-cc67043b.js";import{a as te,b as re,C as se}from"./CardText-bd3e794a.js";import{I as ae,D as T}from"./DropDown-db17f0de.js";import{F as k}from"./FormCheckInput-132a99e2.js";import"./DataKey-95321642.js";import"./useWindow-88a8cae2.js";import"./mergeOptionsWithPopperConfig-8e92920a.js";import"./Button-34612679.js";const q=s.forwardRef(({className:e,bsPrefix:a,as:c="span",...n},l)=>(a=$(a,"input-group-text"),t.jsx(c,{ref:l,className:M(e,a),...n})));q.displayName="InputGroupText";const N=q,ne=e=>t.jsx(N,{children:t.jsx(k,{type:"checkbox",...e})}),oe=e=>t.jsx(N,{children:t.jsx(k,{type:"radio",...e})}),H=s.forwardRef(({bsPrefix:e,size:a,hasValidation:c,className:n,as:l="div",...i},d)=>{e=$(e,"input-group");const f=s.useMemo(()=>({}),[]);return t.jsx(ae.Provider,{value:f,children:t.jsx(l,{ref:d,...i,className:M(n,e,a&&`${e}-${a}`,c&&"has-validation")})})});H.displayName="InputGroup";const ce=Object.assign(H,{Text:N,Radio:oe,Checkbox:ne}),ie="_cards_x7a0n_1",le="_visible_x7a0n_25",v={cards:ie,"no-images":"_no-images_x7a0n_15","loading-images":"_loading-images_x7a0n_19",visible:le},ue="_card_5gbq9_1",de="_header_5gbq9_14",ge="_image_5gbq9_24",me="_loaded_5gbq9_40",fe="_footer_5gbq9_68",he="_category_5gbq9_72",C={card:ue,header:de,"image-wrapper":"_image-wrapper_5gbq9_24",image:ge,loaded:me,"loading-img":"_loading-img_5gbq9_43","loading-image":"_loading-image_5gbq9_1",footer:fe,category:he};function pe({title:e,id:a,category:c,stateToListenTo:n}){const[l,i]=ee({title:e,id:a,size:"medium"});return s.useEffect(()=>{i()},[n]),t.jsxs(K,{to:`/views?id=${a}`,className:`card text-center ${C.card}`,children:[t.jsx(te,{className:C.header,children:t.jsx("h2",{children:e})}),l,t.jsx(re,{className:C.footer,children:t.jsxs(se,{className:C.category,children:["Category: ",c]})})]})}const S={"search-bar-wrapper":"_search-bar-wrapper_fc2ct_1","search-section":"_search-section_fc2ct_6","search-input":"_search-input_fc2ct_6","spinner-wrapper":"_spinner-wrapper_fc2ct_14"},_e=["All",...Q],xe=["Date","Title","Category"];function ye(e){const[a,c]=s.useState(!1),[n,l]=s.useState("");s.useEffect(()=>{c(!0);const o=setTimeout(()=>{var g;(g=e.onChange)==null||g.call(e,n),c(!1)},350);return()=>{clearTimeout(o),c(!1)}},[n]);const i=o=>{var g;(g=e.onSelectCategory)==null||g.call(e,o)},d=o=>{var g;(g=e.onSelectSort)==null||g.call(e,o)},f=o=>{l(o.target.value)};return t.jsxs("div",{className:S["search-bar-wrapper"],children:[t.jsxs(ce,{className:S["search-section"],children:[t.jsx("input",{onChange:f,type:"text",className:`form-control ${S["search-input"]}`,placeholder:"Search..."}),t.jsx(T,{title:"Sort by",onSelect:d,categories:xe,default:"Date"}),t.jsx(T,{title:"Filter",onSelect:i,categories:_e,default:"All"})]}),a&&t.jsx("div",{className:S["spinner-wrapper"],children:t.jsx(X,{animation:"border",variant:"primary"})})]})}const Ie="_error_ldxu1_1",Ce={error:Ie},Se=e=>t.jsx("p",{className:Ce.error,children:e.message}),D=(e,a,c,n)=>async function(l){const i=`${G}/get-slice?limit=${a}&offset=${e}`,f=await(await fetch(i,{method:"GET",headers:{loadedItems:n?n.join(","):"",token:A()??""}})).json();l({type:"ADD_IMAGE_ITEMS",payload:f.data}),c==null||c(),f.hasMore||l({type:"HAS_NO_MORE_ITEMS"})},je=(e,a)=>async function(c){const n=`${G}/get?category=${e.toLowerCase()}`,i=await(await fetch(n,{method:"GET",headers:{loadedItems:a?a.join(","):"",token:A()??""}})).json();c({type:"ADD_IMAGE_ITEMS",payload:i})},we=600;function Ae(){const e=I(r=>r.hasMoreItems),a=I(r=>r.imageItems),c=I(r=>r.loadedCategories),n=Y(),[l,i]=s.useState(!1),[d,f]=s.useState(""),[o,g]=s.useState("All"),[h,L]=s.useState("Date"),F=I(r=>r.initialRender),p=s.useRef(null),[z,O]=s.useState(!1),R=s.useRef(new IntersectionObserver(([r])=>{r.isIntersecting&&!l&&U()},{root:null,rootMargin:"20px",threshold:.1})),j=s.useRef(null),x=s.useRef(3),_=s.useRef(6),y=s.useRef(0),V=s.useRef(a.map(r=>r.id));function B(r){const u=Math.max(Math.ceil(r.clientHeight/we*x.current),x.current);return Math.ceil(u/3)*3}const w=()=>{if(window.innerWidth<768){x.current=1,_.current=3;return}x.current=3,_.current=6},P=async r=>{n({type:"INITIAL_RENDER"}),y.current=r+_.current,i(!0),await n(D(0,y.current,void 0,a.map(u=>u.id))),i(!1)},U=()=>{const r=()=>{i(!1)};n(D(y.current,_.current,r,V.current)),y.current+=_.current},b=()=>{w()};s.useEffect(()=>{(async()=>{if(!e||o==="All"||c.includes(o))return;i(!0);const u=a.filter(m=>m.category===o).map(m=>m.id);await n(je(o,u)),i(!1)})()},[o]),s.useEffect(()=>{O(!0)},[]),s.useEffect(()=>{if(e){if(p.current&&R.current.observe(p.current),w(),j.current){const r=B(j.current);F||P(r),w(),window.addEventListener("resize",b)}return()=>{window.removeEventListener("resize",b),p.current&&R.current.unobserve(p.current)}}},[z]);const E=s.useMemo(()=>{const r=[...a].sort((u,m)=>h==="Title"?u.title.localeCompare(m.title):h==="Category"?u.category.localeCompare(m.category):h==="Date"?new Date(u.date).getTime()-new Date(m.date).getTime():u.id-m.id);return o==="All"&&!d?r:r.filter(u=>{const m=o==="All"||u.category===o,J=!d||u.title.toLowerCase().includes(d.toLowerCase());return m&&J})},[o,d,a,h]),W=!E.length&&!l?t.jsx(Se,{message:"No images found"}):t.jsxs(t.Fragment,{children:[E.map(r=>s.createElement(pe,{stateToListenTo:h,...r,key:r.id})),t.jsx(Z,{ref:p,fullScreen:!1,className:`${v["loading-images"]} ${e&&o==="All"&&!d?v.visible:""}`})]});return t.jsxs(t.Fragment,{children:[t.jsx(ye,{onSelectCategory:g,onChange:f,onSelectSort:L}),t.jsx("div",{className:v.cards,ref:j,children:W})]})}export{Ae as default};
