import { ButtonItem, PanelSection, PanelSectionRow } from "@decky/ui";
import { callable, definePlugin, toaster } from "@decky/api";
import { useEffect, useState } from "react";
import { FaSdCard } from "react-icons/fa";

type Card={path:string;fstype:string;label:string;uuid:string;size:number;mountpoints:string[];readonly:boolean;model:string};
type Result={ok:boolean;stage:string;message:string;fsck_code?:number;repaired?:boolean;log?:string};
const listCards=callable<[],Card[]>("list_cards");
const repair=callable<[path:string],Result>("repair");

function Content(){
 const [cards,setCards]=useState<Card[]>([]); const [busy,setBusy]=useState(false); const [status,setStatus]=useState("SD카드를 검색합니다…");
 const refresh=async()=>{try{const found=await listCards();setCards(found);setStatus(found.length?`${found.length}개의 EXT SD/이동식 파티션을 찾았습니다.`:"검사 가능한 EXT SD/이동식 파티션이 없습니다.");}catch(e){setStatus(`검색 실패: ${String(e)}`);}};
 useEffect(()=>{void refresh();},[]);
 const runRepair=async(c:Card)=>{setBusy(true);setStatus(`${c.path} 언마운트 및 검사 중… 게임이나 파일 작업을 종료한 상태로 기다려 주세요.`);try{const r=await repair(c.path);setStatus(`${r.message}${r.log?`\n\n${r.log}`:""}`);toaster.toast({title:r.ok?"SD Card Repair 완료":"SD Card Repair 실패",body:r.message});}catch(e){setStatus(`실행 실패: ${String(e)}`);}finally{setBusy(false);await refresh();}};
 return <><PanelSection title="SD Card Repair"><PanelSectionRow><ButtonItem disabled={busy} onClick={()=>void refresh()}>장치 다시 검색</ButtonItem></PanelSectionRow>{cards.map(c=><PanelSectionRow key={c.path}><ButtonItem disabled={busy||c.readonly} onClick={()=>void runRepair(c)} description={`${c.path} · ${c.fstype} · ${(c.size/1024**3).toFixed(1)} GiB${c.mountpoints.length?` · ${c.mountpoints.join(", ")}`:" · 언마운트됨"}`}>{c.label||c.model||"SD/이동식 EXT"} 검사/복구</ButtonItem></PanelSectionRow>)}</PanelSection><PanelSection title="상태"><PanelSectionRow><div style={{whiteSpace:"pre-wrap",fontSize:"12px"}}>{status}</div></PanelSectionRow></PanelSection></>;
}
export default definePlugin(()=>({name:"SD Card Repair",titleView:<div>SD Card Repair</div>,content:<Content/>,icon:<FaSdCard/>}));
