import{r as a,h as u,j as s,S as $}from"./index-a25acccf.js";const p="_spinner_18e7i_36",I="_image_18e7i_12",x="_loaded_18e7i_61",w="_visible_18e7i_61",n={"image-wrapper":"_image-wrapper_18e7i_12","loading-img":"_loading-img_18e7i_15","loading-image":"_loading-image_18e7i_1","spinner-wrapper":"_spinner-wrapper_18e7i_36",spinner:p,image:I,loaded:x,visible:w},j=e=>{const[_,f]=a.useState(!1),r=a.useRef(null),[t,v]=a.useState(e.defaultImageShouldLoad??!1),o=`${u}/get-image?id=${e.id}&size=small`,m=`${u}/get-image?id=${e.id}&size=${e.size??"large"}`,l=a.useRef(!1),i=a.useRef(null);a.useEffect(()=>{if(l.current)return;const c=new Image;if(c.src=o,!t)return;const g=new Image;g.src=m,g.onload=()=>{f(!0)},l.current=!0},[e.id,t]),a.useEffect(()=>(i.current=new IntersectionObserver(([c])=>{v(c.isIntersecting)},{root:null,rootMargin:"0px",threshold:.1}),r.current&&i.current.observe(r.current),()=>{r.current&&i.current.unobserve(r.current)}),[]);const b=()=>{i.current.unobserve(r.current),i.current.observe(r.current)};let d=s.jsx("img",{alt:e.title,src:m,loading:"lazy",className:`${e.imageClassName??""} ${n.image} ${t?n.visible:""} ${_?n.loaded:""}`});return!t&&!l.current&&(d=null),[s.jsxs("div",{ref:r,className:`${e.wrapperClassName} ${n["image-wrapper"]}`,children:[s.jsx("div",{className:`${n["loading-img"]} ${e.loadingImageClassName??""}`,children:s.jsx("img",{src:o,alt:e.title})}),s.jsx("div",{className:n["spinner-wrapper"],children:s.jsx($,{className:n.spinner,variant:"primary",animation:"border"})}),d]}),b]};export{j as u};
