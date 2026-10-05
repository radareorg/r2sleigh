#include <mutex>
#include <stdexcept>

#include "bridge.hh"
#include "rust/cxx.h"
#include "libsla-sys/src/sys.rs.h"

// Copied from architecture.cc
ElementId ELEM_PROCESSOR_SPEC = ElementId("processor_spec",147);

RustAssemblyEmitProxy::RustAssemblyEmitProxy(RustAssemblyEmit &emit)
    : inner(emit) {
}

void RustAssemblyEmitProxy::dump(
    const Address &addr,
    const std::string &mnemonic,
    const std::string &body
) {
    inner.dump(addr, mnemonic, body);
}

void RustPcodeEmitProxy::dump(
    const Address &addr,
    OpCode op_code,
    VarnodeData *outvar,
    VarnodeData *vars,
    int4 len
) {
    std::vector<VarnodeData> inputs(vars, vars + len);
    inner.dump(addr, op_code, outvar, inputs);
}

RustLoadImageProxy::RustLoadImageProxy() : LoadImage("undefined") { }

void RustLoadImageProxy::loadFill(uint1 *output_buf, int4 size, const Address &addr) {
    if (inner == nullptr) {
        throw std::runtime_error(std::string("inner image loader is null"));
    }

    try {
        inner->load_fill(output_buf, size, addr);
    } catch (const rust::Error& e) {
        throw DataUnavailError(string(e.what()));
    }
}

string RustLoadImageProxy::getArchType() const {
    return "undefined";
}

void RustLoadImageProxy::adjustVma(long adjust) {
    // TODO
}

RegisterVarnodeName::RegisterVarnodeName(std::pair<VarnodeData, std::string> pair) : pair(pair) {}
const VarnodeData& RegisterVarnodeName::getVarnode() const {
    return std::get<0>(pair);
}
const std::string& RegisterVarnodeName::getName() const {
    return std::get<1>(pair);
}

SleighProxy::SleighProxy(unique_ptr<RustLoadImageProxy> loader, unique_ptr<ContextDatabase> context)
    : Sleigh(loader.get(), context.get()), loader(move(loader)), context(move(context)) {
}

unique_ptr<SleighProxy> construct_new_sleigh(unique_ptr<ContextDatabase> context) {
    auto loader = std::unique_ptr<RustLoadImageProxy>(new RustLoadImageProxy());
    return std::unique_ptr<SleighProxy>(new SleighProxy(move(loader), move(context)));
}

unique_ptr<ContextDatabase> construct_new_context() {
    return std::unique_ptr<ContextDatabase>(new ContextInternal());
}

RustPcodeEmitProxy::RustPcodeEmitProxy(RustPcodeEmit &emit)
    : inner(emit) {
}

void initialize_element_id() {
    ElementId::initialize();
}

void initialize_attribute_id() {
    AttributeId::initialize();
}

unique_ptr<Address> getAddress(const VarnodeData &data) {
    return std::unique_ptr<Address>(new Address(data.space, data.offset));
}

uint4 getSize(const VarnodeData &data) {
    return data.size;
}

const Document& parseDocumentIntoStore(DocumentStorage &store, const std::string &data) {
    std::stringstream ss;
    ss << data;
    
    // The XML parser references global state. Must guard this with a lock
    static std::mutex parseDocumentMutex;
    const std::lock_guard<std::mutex> lock(parseDocumentMutex);
    return *store.parseDocument(ss);
}

const Element& getDocumentRoot(const Document& document) {
    return *document.getRoot();
}

void parseDocumentAndRegisterRootElement(DocumentStorage &store, const std::string &data) {
    auto& doc = parseDocumentIntoStore(store, data);
    store.registerTag(doc.getRoot());
}

void SleighProxy::parseProcessorConfig(const DocumentStorage &store) {
    // This logic lives in architecture.cc which is not exposed in libsla.
    const Element *element = store.getTag("processor_spec");
    if (element == (const Element*)0) {
        throw LowlevelError("No processor_spec tag found");
    }

    XmlDecode decoder(this, element);
    uint4 elementId = decoder.openElement(ELEM_PROCESSOR_SPEC);
    for (;;) {
        uint4 subId = decoder.peekElement();
        if (subId == 0) {
            break;
        } else if (subId != ELEM_CONTEXT_DATA) {
            // Intentionally skipping non-context elements since this does not fully implement the processor spec
            // TODO There is not explicit logic for opening and closing an unknown element.
            // Build should include architecture.cc to at least ensure the elements are understood.
            decoder.openElement();
            decoder.closeElementSkipping(subId);
        } else {
            context->decodeFromSpec(decoder);
        }
    }
}

std::unique_ptr<std::string> SleighProxy::getRegisterNameProxy(AddrSpace *base, uintb off, int4 size) const {
    return std::unique_ptr<std::string>(new std::string(getRegisterName(base, off, size)));
}


std::unique_ptr<std::vector<RegisterVarnodeName>> SleighProxy::getAllRegistersProxy() const {
    std::map<VarnodeData, std::string> regmap;
    getAllRegisters(regmap);

    auto reglist = std::unique_ptr<std::vector<RegisterVarnodeName>>(new std::vector<RegisterVarnodeName>());
    for (auto &regmapEntry : regmap) {
        reglist->push_back(RegisterVarnodeName(regmapEntry));
    }

    return reglist;
}

/// The names of the language's user-defined p-code operations, indexed by the
/// identifier a CALLOTHER carries. `SleighBase` already keeps this list; without
/// an accessor a caller sees only the index, which names nothing on its own.
std::unique_ptr<std::vector<std::string>> SleighProxy::getUserOpNamesProxy() const {
    auto names = std::unique_ptr<std::vector<std::string>>(new std::vector<std::string>());
    getUserOpNames(*names);
    return names;
}

/// Discard every parser context cached by instruction address while retaining
/// the decoded Sleigh specification. Ghidra's public reset path rebuilds the
/// context and disassembly caches without decoding the specification again.
void SleighProxy::clearCache(const DocumentStorage &processorSpec) {
    context = construct_new_context();
    reset(loader.get(), context.get());
    DocumentStorage store;
    initialize(store);
    parseProcessorConfig(processorSpec);
}

void SleighProxy::initializeFromSla(const std::string &sla) {
    std::stringstream slaStream(sla);

    // This is based on the code in Sleigh::initialize
    if (!isInitialized()) {
        sla::FormatDecode decoder(this);
        decoder.ingestStream(slaStream);
        decode(decoder);
    }

    if (isInitialized()) {
        // Dummy store, will not be accessed if initialized.
        // Still need to call Sleigh::initialize to finish initialization
        DocumentStorage store;
        initialize(store);
    } else {
        throw LowlevelError("Failed to initialize sleigh");
    }
}

void SleighProxy::initializeFromRawSla(const std::string &sla) {
    std::stringstream slaStream(sla);

    // This is based on the code in Sleigh::initialize
    if (!isInitialized()) {
        RawFormatDecode decoder(this);
        decoder.ingestStream(slaStream);
        decode(decoder);
    }

    if (isInitialized()) {
        // Dummy store, will not be accessed if initialized.
        // Still need to call Sleigh::initialize to finish initialization
        DocumentStorage store;
        initialize(store);
    } else {
        throw LowlevelError("Failed to initialize sleigh");
    }
}

int4 SleighProxy::disassemblePcode(const RustLoadImage &loadImage, RustPcodeEmit &emit, const Address &baseaddr) const {
    // The loader is stored in the loader proxy only for as long as this manager lives
    RustLoadImageManager manager { *loader.get(), loadImage };

    auto proxy = RustPcodeEmitProxy(emit);
    return Sleigh::oneInstruction(proxy, baseaddr);
}

int4 SleighProxy::disassembleNative(const RustLoadImage &loadImage, RustAssemblyEmit &emit, const Address &baseaddr) const {
    // The loader is stored in the loader proxy only for as long as this manager lives
    RustLoadImageManager manager { *loader.get(), loadImage };

    auto proxy = RustAssemblyEmitProxy(emit);
    return Sleigh::printAssembly(proxy, baseaddr);
}

RustLoadImageManager::RustLoadImageManager(RustLoadImageProxy &proxy, const RustLoadImage &loadImage)
    : proxy(proxy) {
    this->proxy.setInner(loadImage);
}

RustLoadImageManager::~RustLoadImageManager() {
    this->proxy.resetInner();
}

const int4 RawFormatDecode::IN_BUFFER_SIZE = 4096;

RawFormatDecode::RawFormatDecode(const AddrSpaceManager *spcManager)
  : PackedDecode(spcManager)
{
    inBuffer = new uint1[IN_BUFFER_SIZE];
}

RawFormatDecode::~RawFormatDecode(void) {
    delete[] inBuffer;
}


void RawFormatDecode::ingestStream(istream &s) {
    uint1 *outBuf;
    int4 outAvail = 0;
    while (true) {
        s.read((char *)inBuffer,IN_BUFFER_SIZE);
        int4 gcount = s.gcount();
        if (gcount == 0)
            break;
        int4 inAvail = gcount;
        do {
            if (outAvail == 0) {
                outBuf = allocateNextInputBuffer(0);
                outAvail = BUFFER_SIZE;
            }
            int4 copySize = std::min(outAvail, inAvail);
            memcpy(outBuf + (BUFFER_SIZE - outAvail), inBuffer + (gcount - inAvail), copySize);
            outAvail -= copySize;
            inAvail -= copySize;
        } while(outAvail == 0);
    }

    endIngest(BUFFER_SIZE - outAvail);
}
