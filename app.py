import os
from tensorflow import keras
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score,confusion_matrix,classification_report
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import cv2
import pickle
import pefile
import math

from flask import Flask, render_template, request
app = Flask(__name__)

path = os.getcwd()
UPLOAD_FOLDER = os.path.join(path, 'uploads')

if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/")
def home():
    print(app.config['UPLOAD_FOLDER'])
    return render_template("home.html")

@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    if request.method == "GET":
        return render_template("analyze.html")
    else:
        if 'file' not in request.files:
            return 'No file part'

        file = request.files['file']

        if file.filename == '':
            return 'No selected file'

        if file:
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))

#malware features dictionary
    model_features = {}

    malware_file = file.filename

    pe = pefile.PE(malware_file)

    machine = pe.FILE_HEADER.Machine
    model_features["Machine"] = machine

    sizeOfOptionalHeader = pe.FILE_HEADER.SizeOfOptionalHeader
    model_features["SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader

    characteristics = pe.FILE_HEADER.Characteristics
    model_features["Characteristics"] = characteristics

    majorLinkerVersion = pe.OPTIONAL_HEADER.MajorLinkerVersion
    model_features["MajorLinkerVersion"] = majorLinkerVersion

    minorLinkerVersion = pe.OPTIONAL_HEADER.MinorLinkerVersion
    model_features["MinorLinkerVersion"] = minorLinkerVersion

    sizeOfCode = pe.OPTIONAL_HEADER.SizeOfCode
    model_features["SizeOfCode"] = sizeOfCode

    sizeOfInitializedData = pe.OPTIONAL_HEADER.SizeOfInitializedData
    model_features["SizeOfInitializedData"] = sizeOfInitializedData

    sizeOfUninitializedData = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    model_features["SizeOfUninitializedData"] = sizeOfUninitializedData

    addressOfEntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    model_features["AddressOfEntryPoint"] = addressOfEntryPoint

    baseOfCode = pe.OPTIONAL_HEADER.BaseOfCode
    model_features["BaseOfCode"] = baseOfCode

    try:
        baseOfData = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        baseOfData = 0
    model_features["BaseOfData"] = baseOfData

    image_base = pe.OPTIONAL_HEADER.ImageBase
    model_features["ImageBase"] = image_base

    sectionAlignment = pe.OPTIONAL_HEADER.SectionAlignment
    model_features["SectionAlignment"] = sectionAlignment

    fileAlignment = pe.OPTIONAL_HEADER.FileAlignment
    model_features["FileAlignment"] = fileAlignment

    majorOSVer = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    model_features["MajorOperatingSystemVersion"] = majorOSVer

    minorOSVer = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    model_features["MinorOperatingSystemVersion"] = minorOSVer

    majorImgVer = pe.OPTIONAL_HEADER.MajorImageVersion
    model_features["MajorImageVersion"] = majorImgVer

    minorImgVer = pe.OPTIONAL_HEADER.MinorImageVersion
    model_features["MinorImageVersion"] = minorImgVer

    majorSubsysVer = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    model_features["MajorSubsystemVersion"] = majorSubsysVer

    minorSubsysVer = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    model_features["MinorSubsystemVersion"] = minorSubsysVer

    sizeOfImg = pe.OPTIONAL_HEADER.SizeOfImage
    model_features["SizeOfImage"] = sizeOfImg

    sizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders
    model_features["SizeOfHeaders"] = sizeOfHeaders

    checksum = pe.OPTIONAL_HEADER.CheckSum
    model_features["CheckSum"] = checksum

    subsys = pe.OPTIONAL_HEADER.Subsystem
    model_features["Subsystem"] = subsys

    dllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    model_features["DllCharacteristics"] = dllCharacteristics

    sizeOfStackReserve = pe.OPTIONAL_HEADER.SizeOfStackReserve
    model_features["SizeOfStackReserve"] = sizeOfStackReserve

    sizeOfStackCommit = pe.OPTIONAL_HEADER.SizeOfStackCommit
    model_features["SizeOfStackCommit"] = sizeOfStackCommit

    sizeOfHeapReserve = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    model_features["SizeOfHeapReserve"] = sizeOfHeapReserve

    sizeOfHeapCommit = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    model_features["SizeOfHeapCommit"] = sizeOfHeapCommit

    loaderFlags = pe.OPTIONAL_HEADER.LoaderFlags
    model_features["LoaderFlags"] = loaderFlags

    noOfRvaSizes = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    model_features["NumberOfRvaAndSizes"] = noOfRvaSizes

    sectionsNb = pe.FILE_HEADER.NumberOfSections
    model_features["SectionsNb"] = sectionsNb

    
    def calculate_entropy(data):
        entropy = 0
        if len(data) > 0:
            for x in range(256):
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy -= p_x * math.log(p_x, 2)
        return entropy

    def mean_section_entropy(pe):
        section_entropies = []
        for section in pe.sections:
            entropy = calculate_entropy(section.get_data())
            section_entropies.append(entropy)
        if section_entropies:
            mean_entropy = sum(section_entropies) / len(section_entropies)
            return mean_entropy
        else:
            return None

    model_features["SectionsMeanEntropy"] = mean_section_entropy(pe)

    def min_section_entropy(pe):
        section_entropy = calculate_entropy(pe.sections[0].get_data())
        for section in pe.sections[1:]:
            entropy = calculate_entropy(section.get_data())
            if entropy < section_entropy:
                section_entropy = entropy
        return section_entropy

    model_features["SectionsMinEntropy"] = min_section_entropy(pe)

    def max_section_entropy(pe):
        section_entropy = calculate_entropy(pe.sections[0].get_data())
        for section in pe.sections[1:]:
            entropy = calculate_entropy(section.get_data())
            if entropy > section_entropy:
                section_entropy = entropy
        return section_entropy

    model_features["SectionsMaxEntropy"] = max_section_entropy(pe)

    def get_section_raw_data_size(peSection):
        return peSection.SizeOfRawData

    def sections_mean_rawsize(pe):
        sections_raw = []
        for section in pe.sections:
            rawsize = get_section_raw_data_size(section)
            sections_raw.append(rawsize)
        if sections_raw:
            meanRAW = sum(sections_raw) / len(sections_raw)
            return meanRAW
        else:
            return None

    model_features["SectionsMeanRawsize"] = sections_mean_rawsize(pe)

    def sections_min_rawsize(pe):
        section_raw = get_section_raw_data_size(pe.sections[0])
        for section in pe.sections[1:]:
            rawsize = get_section_raw_data_size(section)
            if rawsize < section_raw:
                section_raw = rawsize
        return section_raw

    model_features["SectionsMinRawsize"] = sections_min_rawsize(pe)

    def sections_max_rawsize(pe):
        section_raw = get_section_raw_data_size(pe.sections[0])
        for section in pe.sections[1:]:
            rawsize = get_section_raw_data_size(section)
            if rawsize > section_raw:
                section_raw = rawsize
        return section_raw

    model_features["SectionMaxRawsize"] = sections_max_rawsize(pe)

    def get_virtual_size(peSection):
        return peSection.Misc_VirtualSize

    def sections_mean_virtual_size(pe):
        section_virts = []
        for section in pe.sections:
            virtSize = get_virtual_size(section)
            section_virts.append(virtSize)
        if section_virts:
            meanVirt = sum(section_virts) / len(section_virts)
            return meanVirt
        else:
            return None

    model_features["SectionsMeanVirtualsize"] = sections_mean_virtual_size(pe)

    def sections_min_virtsize(pe):
        section_virt = get_virtual_size(pe.sections[0])
        for section in pe.sections[1:]:
            virtsize = get_virtual_size(section)
            if virtsize < section_virt:
                section_virt = virtsize
        return section_virt

    model_features["SectionsMinVirtualsize"] = sections_min_virtsize(pe)

    def sections_max_virtsize(pe):
        section_virt = get_virtual_size(pe.sections[0])
        for section in pe.sections[1:]:
            virtsize = get_virtual_size(section)
            if virtsize > section_virt:
                section_virt = virtsize
        return section_virt

    model_features["SectionMaxVirtualsize"] = sections_max_virtsize(pe)

    def importsNbDll(pe):
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            imported_dlls = set()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imported_dlls.add(entry.dll.decode())
            return len(imported_dlls)
        else:
            return 0

    model_features["ImportsNbDLL"] = importsNbDll(pe)

    def importsNb(pe):
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            total_imports = 0
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                total_imports += len(entry.imports)
            return total_imports
        else:
            return 0

    model_features["ImportsNb"] = importsNb(pe)

    def importsNbOrdinal(pe):
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            total_ordinal_imports = 0
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.ordinal is not None:
                        total_ordinal_imports += 1
            return total_ordinal_imports
        else:
            return 0

    model_features["ImportsNbOrdinal"] = importsNbOrdinal(pe)

    def exportNb(pe):
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        else:
            return 0

    model_features["ExportNb"] = exportNb(pe)

    def resourcesNb(pe):
        res = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                res += 1
            return res
        else:
            return res

    model_features["ResourcesNb"] = resourcesNb(pe)

    def mean_resources_entropy(pe):
        resource_section = None
        for section in pe.sections:
            if section.Name.strip(b'\x00') == b'.rsrc':
                resource_section = section
                break
        if resource_section:
            entropies = []
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        offset = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        data = pe.get_memory_mapped_image()[offset:offset+size]
                        entropies.append(calculate_entropy(data))
            if entropies:
                mean_entropy = sum(entropies) / len(entropies)
                return mean_entropy
        return 0

    model_features["ResourcesMeanEntropy"] = mean_resources_entropy(pe)

    def min_resources_entropy(pe):
        resource_section = None
        min_entropy = float('inf')

        for section in pe.sections:
            if section.Name.strip(b'\x00') == b'.rsrc':
                resource_section = section
                break

        if resource_section:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        offset = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        data = pe.get_memory_mapped_image()[offset:offset+size]
                        entropy = calculate_entropy(data)
                        min_entropy = min(min_entropy, entropy)

        if min_entropy == float('inf'):
            return 0
        else:
            return min_entropy

    model_features["ResourcesMinEntropy"] = min_resources_entropy(pe)

    def max_resources_entropy(pe):
        resource_section = None
        max_entropy = float('-inf')

        for section in pe.sections:
            if section.Name.strip(b'\x00') == b'.rsrc':
                resource_section = section
                break

        if resource_section:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        offset = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        data = pe.get_memory_mapped_image()[offset:offset+size]
                        entropy = calculate_entropy(data)
                        max_entropy = max(max_entropy, entropy)

        if max_entropy == float('-inf'):
            return 0
        else:
            return max_entropy

    model_features["ResourcesMaxEntropy"] = max_resources_entropy(pe)

    def resources_mean_size(pe):
        resource_section = None
        for section in pe.sections:
            if section.Name.strip(b'\x00') == b'.rsrc':
                resource_section = section
                break
        if resource_section:
            reslen = 0
            size = 0
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        reslen += 1
                        size += resource_lang.data.struct.Size
            resMean = size / reslen
            return resMean
        else:
            return 0

    model_features["ResourcesMeanSize"] = resources_mean_size(pe)

    def resources_min_size(pe):
        resource_section = None
        for section in pe.sections:
            if section.Name.strip(b'\x00') == b'.rsrc':
                resource_section = section
                break
        if resource_section:
            minSize = float('inf')
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        size = resource_lang.data.struct.Size
                        minSize = min(minSize, size)
            return minSize
        else:
            return 0

    model_features["ResourcesMinSize"] = resources_min_size(pe)

    def resources_max_size(pe):
        resource_section = None
        for section in pe.sections:
            if section.Name.strip(b'\x00') == b'.rsrc':
                resource_section = section
                break
        if resource_section:
            maxSize = float('-inf')
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        size = resource_lang.data.struct.Size
                        maxSize = max(maxSize, size)
            return maxSize
        else:
            return 0

    model_features["ResourcesMaxSize"] = resources_max_size(pe)

    def get_load_config_size(pe):
        load_config_size = 0
        try:
            load_config = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']]
            load_config_size = load_config.Size
        except AttributeError:
            load_config_size = 0
        return load_config_size

    model_features["LoadConfigurationSize"] = get_load_config_size(pe)

    def get_version_info_size(pe):
        version_info_size = 0
        try:
            version_info = pe.DIRECTORY_ENTRY_RESOURCE.entries[pefile.RESOURCE_TYPE['RT_VERSION']][0]
            version_info_size = version_info.directory.entries[0].data.struct.Size
        except (AttributeError, KeyError, IndexError):
            version_info_size = 0
        return version_info_size

    model_features["VersionInformationSize"] = get_version_info_size(pe)


    for k,v in model_features.items():
        print(f"{k}: {v}")
    clf = pickle.loads(open(os.path.join('classifier.pkl'),'rb').read())
    features = pickle.loads(open(os.path.join('features2.pkl'),'rb').read())

    #extracting features from the PE file mentioned in the argument
    data = model_features

    #matching it with the features saved in features.pkl
    pe_features = list(map(lambda x:data[x], features))
    print("Features used for classification: ", pe_features)

    #prediciting if the PE is malicious or not based on the extracted features
    res= clf.predict([pe_features])[0]
    print ('The file is %s' % (['malicious', 'legitimate'][res]))
    return render_template("analyze.html", result=res)
        


