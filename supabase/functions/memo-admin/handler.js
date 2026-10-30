const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ORIGIN='https://jademindesk-svg.github.io';
export function createHandler({createClient,env}) {
 return async function handle(req) {
  const origin=req.headers.get('Origin');
  const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Vary':'Origin',
   'Access-Control-Allow-Origin':ORIGIN,'Access-Control-Allow-Headers':'authorization, apikey, content-type, x-client-info',
   'Access-Control-Allow-Methods':'POST, OPTIONS'};
  const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers});
  if(origin&&origin!==ORIGIN)return reply({error:'허용되지 않은 요청입니다.'},403);
  if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
  if(req.method!=='POST')return reply({error:'POST 요청만 허용됩니다.'},405);
  const token=req.headers.get('Authorization')?.match(/^Bearer\s+(.+)$/i)?.[1];
  if(!token)return reply({error:'로그인이 필요합니다.'},401);
  try {
   const url=env('SUPABASE_URL');
   const parseKeys=name=>{try{return JSON.parse(env(name)||'{}').default}catch{return undefined}};
   const publicKey=parseKeys('SUPABASE_PUBLISHABLE_KEYS')||env('SUPABASE_ANON_KEY');
   const secretKey=parseKeys('SUPABASE_SECRET_KEYS')||env('SUPABASE_SERVICE_ROLE_KEY');
   if(!url||!publicKey||!secretKey)return reply({error:'서버 설정을 확인해주세요.'},503);
   const caller=createClient(url,publicKey,{global:{headers:{Authorization:'Bearer '+token}},auth:{persistSession:false,autoRefreshToken:false}});
   const {data:identity,error:authError}=await caller.auth.getUser(token);
   if(authError||!identity?.user)return reply({error:'다시 로그인해주세요.'},401);
   const {data:allowed,error:roleError}=await caller.rpc('is_memo_admin');
   if(roleError||allowed!==true)return reply({error:'관리자만 접근할 수 있습니다.'},403);
   const raw=await req.text();
   if(raw.length>8192)return reply({error:'요청이 너무 큽니다.'},413);
   let body;try{body=JSON.parse(raw)}catch{return reply({error:'올바른 JSON 요청이 필요합니다.'},400)}
   if(!body||typeof body!=='object'||Array.isArray(body))return reply({error:'잘못된 요청입니다.'},400);
   const admin=createClient(url,secretKey,{auth:{persistSession:false,autoRefreshToken:false}});
   const {data:protectedIds,error:idsError}=await admin.rpc('memo_admin_ids');
   if(idsError||!Array.isArray(protectedIds))return reply({error:'관리자 권한 확인에 실패했습니다.'},503);
   const safe=u=>({id:u.id,email:u.email??'',display_name:typeof u.user_metadata?.display_name==='string'?u.user_metadata.display_name:'',
    created_at:u.created_at,last_sign_in_at:u.last_sign_in_at??null,email_confirmed_at:u.email_confirmed_at??null,updated_at:u.updated_at,is_admin:protectedIds.includes(u.id)});
   if(body.action==='list') {
    const page=body.page??1;
    if(!Number.isInteger(page)||page<1||page>100000)return reply({error:'올바른 페이지를 지정해주세요.'},400);
    const {data,error}=await admin.auth.admin.listUsers({page,perPage:20});
    if(error)return reply({error:'회원 목록을 불러오지 못했습니다.'},502);
    return reply({users:data.users.map(safe),page,total:data.total??null,has_more:typeof data.total==='number'?page*20<data.total:(data.nextPage!=null?data.nextPage>page:data.users.length===20)});
   }
   if(!['update','delete'].includes(body.action))return reply({error:'지원하지 않는 작업입니다.'},400);
   if(typeof body.user_id!=='string'||!UUID.test(body.user_id))return reply({error:'올바른 회원 ID가 필요합니다.'},400);
   const {data:target,error:targetError}=await admin.auth.admin.getUserById(body.user_id);
   if(targetError||!target?.user)return reply({error:'회원을 찾을 수 없습니다.'},404);
   if(typeof body.expected_updated_at!=='string'||body.expected_updated_at!==target.user.updated_at)return reply({error:'회원 정보가 변경되었습니다. 새로고침 후 다시 시도해주세요.'},409);
   const isProtected=protectedIds.includes(body.user_id);
   if(body.action==='update') {
    if(typeof body.email!=='string'||body.email.length>254||!/^\S+@\S+\.\S+$/.test(body.email.trim()))return reply({error:'올바른 이메일을 입력해주세요.'},400);
    if(typeof body.display_name!=='string'||body.display_name.trim().length>80)return reply({error:'표시 이름은 80자 이하로 입력해주세요.'},400);
    const email=body.email.trim();
    if(isProtected&&email!==target.user.email)return reply({error:'관리자 로그인 이메일은 이 화면에서 변경할 수 없습니다.'},403);
    const attributes={user_metadata:{...target.user.user_metadata,display_name:body.display_name.trim()}};
    if(email!==target.user.email)attributes.email=email;
    const {data,error}=await admin.auth.admin.updateUserById(body.user_id,attributes);
    if(error)return reply({error:'회원 정보 수정에 실패했습니다. 이메일 중복 여부를 확인해주세요.'},400);
    return reply({user:safe(data.user)});
   }
   if(isProtected)return reply({error:'관리자 계정은 삭제할 수 없습니다.'},403);
   if(typeof body.confirm_email!=='string'||body.confirm_email!==target.user.email)return reply({error:'삭제할 회원의 이메일을 정확히 입력해주세요.'},400);
   const {error}=await admin.auth.admin.deleteUser(body.user_id);
   if(error)return reply({error:'회원 삭제에 실패했습니다. 잠시 후 다시 시도해주세요.'},502);
   return reply({deleted:true});
  }catch{return reply({error:'요청을 처리하지 못했습니다. 잠시 후 다시 시도해주세요.'},500)}
 };
}
