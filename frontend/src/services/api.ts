import axios from 'axios'; import type {Finding,Page,Scan} from '../types/scan';
export const api=axios.create({baseURL:'/api'});
export async function createScan(payload:{target:string;authorized:boolean;max_pages:number;max_depth:number;concurrency:number;follow_redirects:boolean;scan_javascript:boolean;analyze_forms:boolean;passive_only:boolean}){return (await api.post('/scans',payload)).data as {scan_id:string;status:string}}
export async function demoScan(){return (await api.post('/scans/demo')).data as {scan_id:string;status:string}}
export async function listScans(){return (await api.get<Scan[]>('/scans')).data}
export async function getScan(id:string){return (await api.get<Scan>(`/scans/${id}`)).data}
export async function getFindings(id:string){return (await api.get<Finding[]>(`/scans/${id}/findings`)).data}
export async function getPages(id:string){return (await api.get<Page[]>(`/scans/${id}/pages`)).data}
export async function updateFinding(id:string,status:string,reviewer_note:string){return (await api.patch<Finding>(`/findings/${id}`,{status,reviewer_note})).data}
