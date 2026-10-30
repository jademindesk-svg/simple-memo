import { createClient } from 'npm:@supabase/supabase-js@2.49.1';
import { createHandler } from './handler.js';
Deno.serve(createHandler({createClient,env:(name:string)=>Deno.env.get(name)}));
