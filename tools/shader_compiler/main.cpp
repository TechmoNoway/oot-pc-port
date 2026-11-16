// Independent standalone adapter. Its compiler dependency retains its own
// GPL notices in the pinned toolchain sources; the C runtime does not link it.
#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include "shader_recompiler/backend/spirv/emit_spirv.h"
#include "shader_recompiler/environment.h"
#include "shader_recompiler/frontend/ampere/lower_to_maxwell.h"
#include "shader_recompiler/frontend/ampere/program_address_map.h"
#include "shader_recompiler/frontend/ampere/program_capture.h"
#include "shader_recompiler/frontend/maxwell/control_flow.h"
#include "shader_recompiler/frontend/maxwell/translate_program.h"
#include "shader_recompiler/host_translate_info.h"
#include "shader_recompiler/object_pool.h"
#include "shader_recompiler/profile.h"
#include "shader_recompiler/runtime_info.h"

namespace {
struct Request {
    std::array<uint32_t,20> h{};
    std::vector<uint8_t> code;
    std::map<std::pair<uint32_t,uint32_t>,uint32_t> constants;
    std::map<uint32_t,std::array<uint32_t,3>> textures;
};
void require(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
template<class T>void read(std::ifstream& in,T& value){
    in.read(reinterpret_cast<char*>(&value),sizeof(value));require(bool(in),"truncated shader request");
}
Request request(const char* path){
    std::ifstream in(path,std::ios::binary);require(bool(in),"shader request cannot be opened");
    Request r;read(in,r.h);const auto& h=r.h;
    require(h[0]==0x53544f4f && h[1]==1 && h[2]==80,"shader request version/header differs");
    require(h[3]<=2 && h[4]<=65536*16+128 && h[4]>=16 && h[5]<=65536 && h[6]<=65536,"shader request exceeds bounds");
    require(!(h[7]&~7u) && h[15]>=0x10000 && h[15]<=0x10600 && !(h[15]&0xff) &&
        h[16] && h[16]<=65536 && !(h[16]&(h[16]-1)) && h[17] && h[17]<=65536 && !h[18] && !h[19],"shader capabilities are invalid");
    require(h[3]==2 ? h[12]&&h[13]&&h[14]:h[4]>=128,"shader stage/workgroup is invalid");
    require(h[9]<32 && h[10]<=64*1024*1024 && h[11]<=1024*1024,"shader memory metadata exceeds bounds");
    require(h[3]!=2 || (h[12]<=1024 && h[13]<=1024 && h[14]<=1024 &&
        uint64_t(h[12])*h[13]*h[14]<=1024),"shader workgroup exceeds bounds");
    for(uint32_t i=0;i<h[5];++i){std::array<uint32_t,3> v;read(in,v);require(v[0]<32 && !(v[1]&3),"invalid constant query");
        require(r.constants.emplace(std::pair(v[0],v[1]),v[2]).second,"duplicate constant query");}
    for(uint32_t i=0;i<h[6];++i){std::array<uint32_t,4> v;read(in,v);
        require(v[1]<Shader::NUM_TEXTURE_TYPES && v[2]<=static_cast<uint32_t>(Shader::TexturePixelFormat::D32_FLOAT_S8_UINT) &&
            v[3]<=1,"invalid captured texture properties");
        require(r.textures.emplace(v[0],std::array<uint32_t,3>{v[1],v[2],v[3]}).second,"duplicate texture query");}
    r.code.resize(h[4]);in.read(reinterpret_cast<char*>(r.code.data()),r.code.size());require(bool(in),"truncated shader program");
    require(in.peek()==std::char_traits<char>::eof(),"shader request has trailing bytes");return r;
}
class Environment final:public Shader::Environment {
    const Request& r;
    std::vector<uint64_t> lowered;
    const std::array<uint32_t,3>& texture(uint32_t handle){
        auto it=r.textures.find(handle);require(it!=r.textures.end(),"missing captured texture metadata");return it->second;
    }
public:
    explicit Environment(const Request& input):r(input){
        const bool graphics=r.h[3]!=2;const size_t prefix=graphics?128:0;
        require((r.code.size()-prefix)%16==0,"native shader instruction extent is not aligned");
        if(graphics)std::memcpy(&sph,r.code.data(),sizeof(sph));
        stage=r.h[3]==0?Shader::Stage::VertexB:r.h[3]==1?Shader::Stage::Fragment:Shader::Stage::Compute;
        std::vector<Shader::Ampere::Instruction> native((r.code.size()-prefix)/16);
        std::memcpy(native.data(),r.code.data()+prefix,native.size()*16);
        // Lower the complete captured extent. A syntactic EXIT can have a
        // second condition or precede called library code; do not trim there.
        auto result=Shader::Ampere::LowerToMaxwell(native);
        if(!result)throw std::runtime_error("native shader lowering failed: "+std::string(result.error));
        require(result.required_texture_buffer==~0u || result.required_texture_buffer==r.h[9],"captured texture bank differs from lowering");
        lowered.resize(sizeof(sph)/8);std::memcpy(lowered.data(),&sph,sizeof(sph));
        for(auto word:result.instructions){if((lowered.size()*8)%32==0)lowered.push_back(0);lowered.push_back(word);}
        lowered.push_back(0);Shader::Ampere::AppendNativeAddressMap(lowered,result.source_instruction_offsets);
    }
    uint64_t ReadInstruction(uint32_t address)override{
        require(!(address&7)&&address/8<lowered.size(),"compiler read leaves captured code");return lowered[address/8];
    }
    uint32_t TranslateProgramAddress(uint32_t address)const override{
        auto value=Shader::Ampere::NativeProgramAddress(lowered,address);
        require(value.has_value(),"indirect native branch target is not captured");return *value;
    }
    uint32_t ReadCbufValue(uint32_t bank,uint32_t offset)override{
        auto it=r.constants.find({bank,offset});require(it!=r.constants.end(),"missing captured constant-buffer answer");return it->second;
    }
    Shader::TextureType ReadTextureType(uint32_t handle)override{return static_cast<Shader::TextureType>(texture(handle)[0]);}
    Shader::TexturePixelFormat ReadTexturePixelFormat(uint32_t handle)override{return static_cast<Shader::TexturePixelFormat>(texture(handle)[1]);}
    bool IsTexturePixelFormatInteger(uint32_t handle)override{return texture(handle)[2]!=0;}
    uint32_t ReadViewportTransformState()override{return r.h[8];}
    uint32_t TextureBoundBuffer()const override{return r.h[9];}
    uint32_t LocalMemorySize()const override{return r.h[10];}
    uint32_t SharedMemorySize()const override{return r.h[11];}
    std::array<uint32_t,3> WorkgroupSize()const override{return {r.h[12],r.h[13],r.h[14]};}
    bool HasHLEMacroState()const override{return false;}
    std::optional<Shader::ReplaceConstant> GetReplaceConstBuffer(uint32_t,uint32_t)override{return std::nullopt;}
    void Dump(uint64_t,uint64_t)override{}
};
}
int main(int argc,char** argv){
    if(argc==2 && std::string_view(argv[1])=="--version"){
        std::cout<<"oot-shader-tool protocol 1; external Eden/Sirit compiler; see dependency licenses\n";return 0;
    }
    if(argc!=4){std::cerr<<"usage: oot-shader-tool request.bin output.spv reflection.json\n";return 2;}
    try{
        // Dependency debug/experimental environment knobs cannot silently
        // change this protocol's explicit capture/capability inputs.
        for(const char* key:{"EDEN_NX2_TENSOR","EDEN_NX2_UNDEF_ZERO","RX_VK_MESH_NO_ZERO","RX_VK_TASK_CAP",
            "RX_VK_BLOCK_PROBE","RX_VK_FOLLOW_GRAPHICS","RX_VK_FOLLOW_MESH","RX_VK_FOLLOW_STORES",
            "RX_VK_GP_TEST","RX_VK_MESH_FIRST","RX_VK_NO_FOLLOW","RX_VK_NO_EXTREGS","RX_VK_LOG_BRX",
            "RX_VK_MISS_LOG","RX_VK_PTR_DIAG","RX_VK_PTR_SPLIT_FALLBACK"}){
#ifdef _WIN32
            require(_putenv_s(key,"")==0,"cannot clear compiler environment override");
#else
            require(unsetenv(key)==0,"cannot clear compiler environment override");
#endif
        }
        Request r=request(argv[1]);Environment env(r);
        Shader::ObjectPool<Shader::Maxwell::Flow::Block> flow;
        Shader::ObjectPool<Shader::IR::Inst> instructions;Shader::ObjectPool<Shader::IR::Block> blocks;
        Shader::HostTranslateInfo host{};host.min_ssbo_alignment=r.h[16];
        host.support_float64=bool(r.h[7]&1);host.support_float16=bool(r.h[7]&2);host.support_int64=bool(r.h[7]&4);
        host.max_per_stage_descriptor_sampled_images=r.h[17];host.max_per_stage_resources=r.h[17];
        host.max_descriptor_set_samplers=r.h[17];host.max_descriptor_set_uniform_buffers=r.h[17];
        host.max_descriptor_set_storage_buffers=r.h[17];host.max_descriptor_set_sampled_images=r.h[17];
        host.max_descriptor_set_storage_images=r.h[17];
        Shader::Maxwell::Flow::CFG cfg(env,flow,sizeof(Shader::ProgramHeader),true);
        auto program=Shader::Maxwell::TranslateProgram(instructions,blocks,env,cfg,host);
        Shader::Profile profile{};profile.supported_spirv=r.h[15];profile.support_int64=host.support_int64;
        profile.unified_descriptor_binding=true;
        Shader::Backend::Bindings bindings{};Shader::RuntimeInfo runtime{};
        auto spirv=Shader::Backend::SPIRV::EmitSPIRV(profile,runtime,program,bindings);
        require(spirv.size()>=5 && spirv[0]==0x07230203,"compiler did not produce SPIR-V");
        std::ofstream binary(argv[2],std::ios::binary);binary.write(reinterpret_cast<const char*>(spirv.data()),spirv.size()*4);
        require(bool(binary),"SPIR-V output failed");
        std::ofstream meta(argv[3]);meta<<"{\"schema\":1,\"stage\":"<<r.h[3]<<",\"words\":"<<spirv.size()
            <<",\"constant_buffer_mask\":"<<program.info.constant_buffer_mask<<",\"constant_buffer_sizes\":[";
        for(size_t i=0;i<Shader::Info::MAX_CBUFS;++i){if(i)meta<<',';meta<<program.info.constant_buffer_used_sizes[i];}
        meta<<"],\"storage_buffers\":[";
        for(size_t i=0;i<program.info.storage_buffers_descriptors.size();++i){if(i)meta<<',';const auto& b=program.info.storage_buffers_descriptors[i];
            meta<<"{\"bank\":"<<b.cbuf_index<<",\"offset\":"<<b.cbuf_offset<<",\"count\":"<<b.count<<",\"written\":"<<(b.is_written?"true":"false")<<'}';}
        meta<<"],\"textures\":"<<program.info.texture_descriptors.size()<<",\"images\":"<<program.info.image_descriptors.size()
            <<",\"descriptor_binding_count\":"<<bindings.unified<<",\"descriptors\":[";
        uint32_t binding=0;bool first=true;
        auto begin=[&](const char* kind,uint32_t count){if(!first)meta<<',';first=false;
            meta<<"{\"kind\":\""<<kind<<"\",\"set\":0,\"binding\":"<<binding<<",\"count\":"<<count;
            binding+=count;};
        for(const auto& b:program.info.constant_buffer_descriptors){begin("uniform_buffer",b.count);meta<<",\"bank\":"<<b.index<<'}';}
        for(const auto& b:program.info.storage_buffers_descriptors){begin("storage_buffer",b.count);
            meta<<",\"bank\":"<<b.cbuf_index<<",\"offset\":"<<b.cbuf_offset<<",\"written\":"<<(b.is_written?"true":"false")<<'}';}
        for(const auto& b:program.info.texture_buffer_descriptors){begin("uniform_texel_buffer",b.count);
            meta<<",\"bank\":"<<b.cbuf_index<<",\"offset\":"<<b.cbuf_offset<<",\"handle_program\":"<<b.handle_program<<'}';}
        for(const auto& b:program.info.image_buffer_descriptors){begin("storage_texel_buffer",b.count);
            meta<<",\"bank\":"<<b.cbuf_index<<",\"offset\":"<<b.cbuf_offset<<",\"handle_program\":"<<b.handle_program<<'}';}
        for(const auto& b:program.info.texture_descriptors){begin("combined_image_sampler",b.count);
            meta<<",\"bank\":"<<b.cbuf_index<<",\"offset\":"<<b.cbuf_offset<<",\"type\":"<<static_cast<uint32_t>(b.type)
                <<",\"handle_program\":"<<b.handle_program<<",\"secondary\":"<<(b.has_secondary?"true":"false")
                <<",\"secondary_bank\":"<<b.secondary_cbuf_index<<",\"secondary_offset\":"<<b.secondary_cbuf_offset
                <<",\"shift\":"<<b.shift_left<<",\"secondary_shift\":"<<b.secondary_shift_left<<",\"size_shift\":"<<b.size_shift
                <<",\"integer\":"<<(b.is_integer?"true":"false")<<",\"depth\":"<<(b.is_depth?"true":"false")
                <<",\"multisample\":"<<(b.is_multisample?"true":"false")<<'}';}
        for(const auto& b:program.info.image_descriptors){begin("storage_image",b.count);
            meta<<",\"bank\":"<<b.cbuf_index<<",\"offset\":"<<b.cbuf_offset<<",\"type\":"<<static_cast<uint32_t>(b.type)
                <<",\"format\":"<<static_cast<uint32_t>(b.format)<<",\"handle_program\":"<<b.handle_program
                <<",\"size_shift\":"<<b.size_shift<<",\"integer\":"<<(b.is_integer?"true":"false")
                <<",\"read\":"<<(b.is_read?"true":"false")<<",\"written\":"<<(b.is_written?"true":"false")<<'}';}
        require(binding==bindings.unified,"compiler descriptor reflection layout differs");
        meta<<"]}\n";
        require(bool(meta),"shader reflection output failed");return 0;
    }catch(const std::exception& error){std::cerr<<"shader translation failed: "<<error.what()<<'\n';return 1;}
}
