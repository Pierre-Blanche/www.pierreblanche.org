/** @return {boolean} */
const required=(padding)=>{
  const t=parseInt(document.cookie?.split(';')?.find(it=>it.trim().startsWith('st='))?.trim()?.substring(3));
  return isNaN(t)||new Date().getTime()+padding>t*1000;
}
/** @return {Promise<boolean>} */
const request=async()=>{
  let signal=AbortSignal.timeout(30_000);
  try{
    let response=await fetch(
      '/api/auth/credential_request_options',
      {
        credentials:'include',
        signal,
      }
    );
    if(!response.ok) return false;
    const publicKey=PublicKeyCredential.parseRequestOptionsFromJSON(await response.json());
    const credential=await navigator.credentials.get({signal,publicKey});
    if(!credential) return false;
    const body=new FormData();
    body.append('i',new Blob([credential.rawId],{type:'binary/octet-stream'}));
    body.append('s',new Blob([credential.response.signature],{type:'binary/octet-stream'}));
    body.append('u',new Blob([credential.response.userHandle],{type:'binary/octet-stream'}));
    body.append('c',new Blob([credential.response.clientDataJSON],{type:'binary/octet-stream'}));
    body.append('d',new Blob([credential.response.authenticatorData],{type:'binary/octet-stream'}));
    response=await fetch(
      '/api/auth/validate_credential',
      {
        credentials:'include',
        method:'POST',
        body
      }
    );
    if(!response.ok){
      if(PublicKeyCredential.signalUnknownCredential){
        PublicKeyCredential.signalUnknownCredential({
          rpId: credential.rpId,
          credentialId: credential.id
        });
      }
      return false;
    }
    return true;
  }catch(_){
    return false;
  }
};
/** @return {Promise<boolean>} */
const create=async()=>{
  let signal=AbortSignal.timeout(30_000);
  try{
    let response=await fetch(
      '/api/auth/credential_creation_options',
      {
        credentials:'include',
        signal
      }
    );
    if(!response.ok) return false;
    const publicKey=PublicKeyCredential.parseCreationOptionsFromJSON(await response.json());
    const credential=await navigator.credentials.create({signal,publicKey});
    if(!credential) return false;
    const body=new FormData();
    body.append('i',new Blob([credential.rawId],{type:'binary/octet-stream'}));
    body.append('a',credential.response.getPublicKeyAlgorithm().toString());
    body.append('k',new Blob([credential.response.getPublicKey()],{type:'binary/octet-stream'}));
    body.append('c',new Blob([credential.response.clientDataJSON],{type:'binary/octet-stream'}));
    body.append('d',new Blob([credential.response.authenticatorData],{type:'binary/octet-stream'}));
    response=await fetch(
      '/api/auth/record_credential',
      {
        credentials:'include',
        method:'POST',
        body
      }
    );
    return response.ok;
  }catch(_){
    return false;
  }

}
export {required,request,create};