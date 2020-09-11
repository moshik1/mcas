(window.webpackJsonp=window.webpackJsonp||[]).push([[44],{"5vVC":function(e,t,n){"use strict";n.r(t),n.d(t,"Title",(function(){return l})),n.d(t,"_frontmatter",(function(){return s})),n.d(t,"default",(function(){return b}));n("91GP"),n("rGqo"),n("yt8O"),n("Btvt"),n("RW0V"),n("q1tI");var o=n("7ljp"),r=n("013z");n("qKvR");function a(){return(a=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(e[o]=n[o])}return e}).apply(this,arguments)}var i,l=function(){return Object(o.b)("span",null,"First line ",Object(o.b)("br",null)," Second line")},s={},c=(i="PageDescription",function(e){return console.warn("Component "+i+" was not imported, exported, or provided by MDXProvider as global scope"),Object(o.b)("div",e)}),u={Title:l,_frontmatter:s},p=r.a;function b(e){var t=e.components,n=function(e,t){if(null==e)return{};var n,o,r={},a=Object.keys(e);for(o=0;o<a.length;o++)n=a[o],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,["components"]);return Object(o.b)(p,a({},u,n,{components:t,mdxType:"MDXLayout"}),Object(o.b)(c,{mdxType:"PageDescription"},Object(o.b)("p",null,"MDX allows for certain things beyond what markdown is capable of. Content here\nwill discuss using those features to augment or modify the default content\nlayout.")),Object(o.b)("h2",null,"Frontmatter"),Object(o.b)("p",null,"You can declare frontmatter in your ",Object(o.b)("inlineCode",{parentName:"p"},".mdx")," files to provide specific metadata for the theme to use."),Object(o.b)("ul",null,Object(o.b)("li",{parentName:"ul"},Object(o.b)("inlineCode",{parentName:"li"},"title"),": Main page title: search results and SEO"),Object(o.b)("li",{parentName:"ul"},Object(o.b)("inlineCode",{parentName:"li"},"description"),": SEO and search results"),Object(o.b)("li",{parentName:"ul"},Object(o.b)("inlineCode",{parentName:"li"},"keywords"),": just SEO (optional)"),Object(o.b)("li",{parentName:"ul"},Object(o.b)("inlineCode",{parentName:"li"},"hiddenFromSearch"),": if true, page will be excluded from search")),Object(o.b)("pre",null,Object(o.b)("code",a({parentName:"pre"},{className:"language-md"}),"---\ntitle: Markdown\ndescription: Usage instructions for the Markdown component\nkeywords: 'ibm,carbon,gatsby,mdx,markdown'\nhiddenFromSearch: true\n---\n")),Object(o.b)("h2",null,"Smart quotes"),Object(o.b)("p",null,"The theme has a remark for processing straight quotes, into ‘smart’ quotes (”). However, this plugin isn’t able to process text used in custom MDX components.\nWhen using quotes in custom components, content authors should manually use ",Object(o.b)("a",a({parentName:"p"},{href:"https://www.figma.com/design-systems/"}),"“smart quotes”")," to adhere to the IBM Design Language content guidelines."),Object(o.b)("h2",null,"Custom title"),Object(o.b)("p",null,"You can export a ",Object(o.b)("inlineCode",{parentName:"p"},"Title")," component in order to render a unique title for a single page. This is particularly useful for including line breaks at a specific location."),Object(o.b)("p",null,Object(o.b)("strong",{parentName:"p"},"Note:")," You still need to provide a regular string title to the frontmatter for search, navigation, and the HTML header title to work."),Object(o.b)("pre",null,Object(o.b)("code",a({parentName:"pre"},{className:"language-jsx"}),"---\ntitle: MDX\ndescription: custom title page\n---\n\nexport const Title = () => (\n  <span>\n    First line <br /> Second line\n  </span>\n);\n")))}b.isMDXComponent=!0}}]);
//# sourceMappingURL=component---src-pages-guides-mdx-mdx-82ca7bdf1a20cebd520c.js.map