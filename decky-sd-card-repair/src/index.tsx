import { ButtonItem, PanelSection, PanelSectionRow } from "@decky/ui";
import { callable, definePlugin, toaster } from "@decky/api";
import { useEffect, useState } from "react";
import { FaSdCard } from "react-icons/fa";
type Card={path:string;fstype:string;label:string;uuid:string;size:number;mountpoints:string[];readonly:boolean;model:string};
type Result={ok:boolean;stage:string;message:string;log?:string};
type Status={root:boolean;euid:number;e2fsck:string};
const listCards=callable<[],Card[]>("list_cards");
const getStatus=callable<[],Status>("get_status");
const repair=callable<[path:string],Result>("repair");
function Content(){
 const [cards,setCards]=useState<Card[]>([]); const [busy,setBusy]=useState(false); const [root,setRoot]=useState(false); const [status,setStatus]=useState("SD카드를 검색합니다…");
 const refresh=async()=>{try{const found=await listCards();const s=await getStatus();setCards(found);setRoot(s.root);setStatus((s.root?"ROOT 권한 확인됨":"ROOT 권한 없음")+" (EUID="+s.euid+") · e2fsck "+(s.e2fsck?"확인됨":"없음")+"\n"+(found.length?found.length+"개의 EXT SD/이동식 파티션을 찾았습니다.":"검사 가능한 EXT SD/이동식 파티션이 없습니다."));}catch(e){setStatus("검색 실패: "+String(e));}};
 useEffect(()=>{void refresh();},[]);
 const runRepair=async(c:Card)=>{setBusy(true);setStatus(c.path+" 언마운트 → e2fsck -f -y 자동복구 → e2fsck -f -n 재검증 중…");try{const r=await repair(c.path);setStatus(r.message+(r.log?"\n\n"+r.log:""));toaster.toast({title:r.ok?"SD Card Repair 완료":"SD Card Repair 실패",body:r.message});}catch(e){setStatus("실행 실패: "+String(e));}finally{setBusy(false);}};
 return <><PanelSection title="SD Card Repair"><PanelSectionRow><ButtonItem disabled={busy} onClick={()=>void refresh()}>장치 다시 검색</ButtonItem></PanelSectionRow>{!root&&<PanelSectionRow><div>ROOT 권한이 없어 복구를 실행할 수 없습니다. 이 플러그인은 _root 권한으로 설치되어야 합니다.</div></PanelSectionRow>}{cards.map(c=><PanelSectionRow key={c.path}><ButtonItem disabled={busy||c.readonly||!root} onClick={()=>void runRepair(c)} description={c.path+" · "+c.fstype+" · "+(c.size/1024**3).toFixed(1)+" GiB"+(c.mountpoints.length?" · "+c.mountpoints.join(", "):" · 언마운트됨")}>{c.label||c.model||"SD/이동식 EXT"} 자동복구 (-y)</ButtonItem></PanelSectionRow>)}</PanelSection><PanelSection title="상태"><PanelSectionRow><div style={{whiteSpace:"pre-wrap",fontSize:"12px"}}>{status}</div></PanelSectionRow></PanelSection></>;
}
export default definePlugin(()=>({name:"SD Card Repair",titleView:<div>SD Card Repair</div>,content:<Content/>,icon:<FaSdCard/>}));
