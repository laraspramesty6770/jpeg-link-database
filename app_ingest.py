import sqlite3
import hashlib
import shutil
from datetime import datetime
from io import BytesIO
from pathlib import Path

from PIL import Image, ExifTags

import pandas as pd
import streamlit as st
import plotly.express as px

# ==================================================
# 1. KONFIGURASI DASHBOARD
# ==================================================

st.set_page_config(
    page_title="JPEG Camera Signature Dashboard",
    page_icon="📷",
    layout="wide"
)

st.title("📷 JPEG Camera Signature Analysis")
st.caption(
    "Interactive dashboard untuk analisis JPEG camera signature, "
    "metadata, dan hubungan antar gambar."
)

# ==================================================
# 2. UPLOAD DATABASE
# ==================================================

st.sidebar.header("📂 Database")

uploaded_db = st.sidebar.file_uploader(
    "Upload database SQLite (.db)",
    type=["db", "sqlite", "sqlite3"]
)

database_path = st.sidebar.text_input(
    "Atau masukkan lokasi database",
    value="jpeg_link_database.db"
)

if uploaded_db:
    DB_PATH = Path("/tmp") / uploaded_db.name
    DB_PATH.write_bytes(uploaded_db.getvalue())

elif Path(database_path).exists():
    DB_PATH = Path(database_path)

else:
    st.info(
        "Upload file jpeg_link_database.db melalui sidebar "
        "atau letakkan database di folder yang sama dengan app.py."
    )
    st.stop()


# ==================================================
# 3. MEMBACA DATABASE SQLITE
# ==================================================

with sqlite3.connect(DB_PATH) as conn:

    tables = pd.read_sql_query(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table'
        AND name NOT LIKE 'sqlite_%'
        """,
        conn
    )["name"].tolist()

    database_tables = {
        table: pd.read_sql_query(
            f'SELECT * FROM "{table}"',
            conn
        )
        for table in tables
    }


# ==================================================
# 4. FUNGSI BANTU
# ==================================================

def find_column(dataframe, candidates):
    """Mencari nama kolom tanpa memperhatikan huruf besar/kecil."""

    column_map = {
        str(column).lower(): column
        for column in dataframe.columns
    }

    for candidate in candidates:
        if candidate.lower() in column_map:
            return column_map[candidate.lower()]

    for column in dataframe.columns:
        for candidate in candidates:
            if candidate.lower() in str(column).lower():
                return column

    return None


def clean_text(series):
    """Mengubah metadata kosong menjadi Unknown."""

    return (
        series
        .fillna("Unknown")
        .astype(str)
        .replace({
            "": "Unknown",
            "nan": "Unknown",
            "None": "Unknown",
            "<NA>": "Unknown"
        })
    )



# ==================================================
# JPEG INGEST — VALIDASI, EKSTRAKSI, DAN PENYIMPANAN
# ==================================================

def extract_exif_from_bytes(image_bytes):
    """Ekstrak EXIF dari JPEG upload."""
    result = {}
    try:
        image = Image.open(BytesIO(image_bytes))
        exif = image.getexif()
        for tag_id, value in exif.items():
            result[ExifTags.TAGS.get(tag_id, str(tag_id))] = value
        try:
            exif_ifd = exif.get_ifd(ExifTags.IFD.Exif)
            for tag_id, value in exif_ifd.items():
                result[ExifTags.TAGS.get(tag_id, str(tag_id))] = value
        except Exception:
            pass
    except Exception:
        pass
    return result


def exif_scalar(value):
    """Konversi nilai EXIF ke tipe yang dapat disimpan SQLite."""
    if value is None:
        return None
    try:
        if hasattr(value, "numerator") and hasattr(value, "denominator"):
            return float(value.numerator) / float(value.denominator)
        if isinstance(value, tuple) and len(value) == 2:
            return float(value[0]) / float(value[1])
        return value
    except Exception:
        return str(value)


def extract_jpeg_signature_from_bytes(data):
    """DQT/DHT signature; algoritma dipertahankan sesuai versi proyek."""
    dqt_segments = []
    dht_segments = []

    if not data.startswith(b"\xff\xd8"):
        return {"DQT_Count": 0, "DHT_Count": 0, "DQT_Hash": None,
                "DHT_Hash": None, "JPEG_Signature": None}

    i = 2
    while i < len(data) - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        while i < len(data) and data[i] == 0xFF:
            i += 1
        if i >= len(data):
            break
        marker = data[i]
        i += 1
        if marker == 0xD9:
            break
        if marker == 0xD8 or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue
        if i + 2 > len(data):
            break
        segment_length = int.from_bytes(data[i:i + 2], "big")
        if segment_length < 2:
            break
        segment_data = data[i + 2:i + segment_length]
        if marker == 0xDB:
            dqt_segments.append(segment_data)
        elif marker == 0xC4:
            dht_segments.append(segment_data)
        elif marker == 0xDA:
            break
        i += segment_length

    dqt_data = b"".join(dqt_segments)
    dht_data = b"".join(dht_segments)
    dqt_hash = hashlib.sha256(dqt_data).hexdigest() if dqt_data else None
    dht_hash = hashlib.sha256(dht_data).hexdigest() if dht_data else None
    combined_data = b"DQT:" + dqt_data + b"|DHT:" + dht_data
    signature = hashlib.sha256(combined_data).hexdigest() if dqt_data or dht_data else None
    return {"DQT_Count": len(dqt_segments), "DHT_Count": len(dht_segments),
            "DQT_Hash": dqt_hash, "DHT_Hash": dht_hash,
            "JPEG_Signature": signature}


def ingest_uploaded_jpegs(uploaded_files, db_path):
    """Insert JPEG metadata/signatures, then refresh signature prevalence tables."""
    db_path = Path(db_path)
    if not db_path.exists():
        raise FileNotFoundError(f"Database tidak ditemukan: {db_path}")

    backup_path = db_path.with_name(
        f"{db_path.stem}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}{db_path.suffix}"
    )
    shutil.copy2(db_path, backup_path)
    outcomes = []

    with sqlite3.connect(db_path) as conn:
        image_cols = {row[1] for row in conn.execute("PRAGMA table_info(jpeg_images)")}
        if "FullFile_SHA256" not in image_cols:
            conn.execute("ALTER TABLE jpeg_images ADD COLUMN FullFile_SHA256 TEXT")

        existing_hashes = {r[0] for r in conn.execute(
            "SELECT FullFile_SHA256 FROM jpeg_images WHERE FullFile_SHA256 IS NOT NULL"
        )}
        batch_hashes = set()

        for upload in uploaded_files:
            name = Path(upload.name).name
            data = upload.getvalue()
            if not data.startswith(b"\xff\xd8"):
                outcomes.append({"File": name, "Status": "Ditolak: bukan JPEG (SOI marker tidak ditemukan)"})
                continue

            full_hash = hashlib.sha256(data).hexdigest()
            if full_hash in existing_hashes or full_hash in batch_hashes:
                outcomes.append({"File": name, "Status": "Duplikat identik: dilewati"})
                continue
            batch_hashes.add(full_hash)

            try:
                image = Image.open(BytesIO(data))
                image.load()
                width, height = image.size
                exif = extract_exif_from_bytes(data)
                sig = extract_jpeg_signature_from_bytes(data)
                iso = exif.get("ISOSpeedRatings", exif.get("PhotographicSensitivity"))
                try:
                    iso = float(iso) if iso is not None else None
                except Exception:
                    iso = None

                record = {
                    "FileName": name,
                    "RelativePath": f"uploaded/{name}",
                    "Width": width,
                    "Height": height,
                    "FileSize_Bytes": len(data),
                    "Make": str(exif.get("Make")) if exif.get("Make") is not None else None,
                    "Model": str(exif.get("Model")) if exif.get("Model") is not None else None,
                    "Software": str(exif.get("Software")) if exif.get("Software") is not None else None,
                    "DateTime": str(exif.get("DateTime")) if exif.get("DateTime") is not None else None,
                    "DateTimeOriginal": str(exif.get("DateTimeOriginal")) if exif.get("DateTimeOriginal") is not None else None,
                    "FocalLength": exif_scalar(exif.get("FocalLength")),
                    "ISO": iso,
                    "DQT_Count": sig["DQT_Count"],
                    "DHT_Count": sig["DHT_Count"],
                    "DQT_Hash": sig["DQT_Hash"],
                    "DHT_Hash": sig["DHT_Hash"],
                    "JPEG_Signature": sig["JPEG_Signature"],
                    "FullFile_SHA256": full_hash,
                }
                columns = list(record)
                conn.execute(
                    f"INSERT INTO jpeg_images ({', '.join(chr(34)+c+chr(34) for c in columns)}) "
                    f"VALUES ({', '.join('?' for _ in columns)})",
                    [record[c] for c in columns]
                )
                outcomes.append({"File": name, "Status": "Berhasil disimpan"})
            except Exception as exc:
                outcomes.append({"File": name, "Status": f"Gagal diproses: {exc}"})

        # Hitung prevalence dari seluruh records. Klasifikasi mengikuti rentang yang disepakati.
        counts = conn.execute("""
            SELECT JPEG_Signature, COUNT(*)
            FROM jpeg_images
            WHERE JPEG_Signature IS NOT NULL
            GROUP BY JPEG_Signature
        """).fetchall()
        conn.execute("DELETE FROM jpeg_signatures")
        for signature, count in counts:
            classification = "Unique (1)" if count == 1 else (
                "Shared (2)" if count == 2 else ("Shared (3-5)" if count <= 5 else "Common (>5)")
            )
            conn.execute(
                "INSERT INTO jpeg_signatures (JPEG_Signature, Image_Count, Classification) VALUES (?, ?, ?)",
                (signature, count, classification)
            )

        # Tabel link analysis memiliki kolom gambar + Image_Count + Classification.
        conn.execute("DELETE FROM jpeg_link_analysis")
        conn.execute("""
            INSERT INTO jpeg_link_analysis (
                FileName, RelativePath, Width, Height, FileSize_Bytes, Make, Model,
                Software, DateTime, DateTimeOriginal, FocalLength, ISO, DQT_Count,
                DHT_Count, DQT_Hash, DHT_Hash, JPEG_Signature, Image_Count, Classification
            )
            SELECT i.FileName, i.RelativePath, i.Width, i.Height, i.FileSize_Bytes,
                   i.Make, i.Model, i.Software, i.DateTime, i.DateTimeOriginal,
                   i.FocalLength, i.ISO, i.DQT_Count, i.DHT_Count, i.DQT_Hash,
                   i.DHT_Hash, i.JPEG_Signature, s.Image_Count, s.Classification
            FROM jpeg_images i
            LEFT JOIN jpeg_signatures s ON i.JPEG_Signature = s.JPEG_Signature
        """)
        conn.commit()

    return outcomes, backup_path

# ==================================================
# 5. IDENTIFIKASI TABEL GAMBAR DAN SIGNATURE
# ==================================================

images_df = None
signatures_df = None

for table_name, dataframe in database_tables.items():

    table_name_lower = table_name.lower()

    if "jpeg_images" in table_name_lower:
        images_df = dataframe

    elif "jpeg_signatures" in table_name_lower:
        signatures_df = dataframe


# Fallback jika nama tabel berbeda

if images_df is None:

    for dataframe in database_tables.values():

        if (
            find_column(dataframe, ["FileName"])
            and find_column(dataframe, ["JPEG_Signature"])
        ):
            images_df = dataframe
            break


if signatures_df is None:

    for dataframe in database_tables.values():

        if (
            find_column(dataframe, ["Classification"])
            and find_column(dataframe, ["Image_Count"])
        ):
            signatures_df = dataframe
            break


# ==================================================
# 6. KPI DASHBOARD
# ==================================================

total_images = (
    len(images_df)
    if images_df is not None
    else 0
)

signature_column = (
    find_column(images_df, ["JPEG_Signature"])
    if images_df is not None
    else None
)

if signature_column:

    total_signatures = images_df[
        signature_column
    ].nunique()

elif signatures_df is not None:

    signature_column = find_column(
        signatures_df,
        ["JPEG_Signature"]
    )

    total_signatures = (
        signatures_df[signature_column].nunique()
        if signature_column
        else 0
    )

else:
    total_signatures = 0


make_column = (
    find_column(images_df, ["Make", "Manufacturer"])
    if images_df is not None
    else None
)

model_column = (
    find_column(images_df, ["Model", "Camera_Model"])
    if images_df is not None
    else None
)


if make_column:

    total_makes = (
        clean_text(images_df[make_column])
        .replace("Unknown", pd.NA)
        .nunique()
    )

else:
    total_makes = 0


if model_column:

    total_models = (
        clean_text(images_df[model_column])
        .replace("Unknown", pd.NA)
        .nunique()
    )

else:
    total_models = 0


kpi1, kpi2, kpi3, kpi4 = st.columns(4)

kpi1.metric("JPEG Records", total_images)
kpi2.metric("Unique Signatures", total_signatures)
kpi3.metric("Camera Makes", total_makes)
kpi4.metric("Camera Models", total_models)


st.divider()


# ==================================================
# 7. TAB DASHBOARD
# ==================================================

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview",
    "🔎 Signature Explorer",
    "🖼️ Image & Metadata",
    "🗃️ SQLite Database",
    "➕ Add JPEGs / Ingest"
])



# ==================================================
# TAB 5 — ADD JPEGs / INGEST
# ==================================================

with tab5:
    st.subheader("➕ Add JPEGs to Database")
    st.info(
        "Upload JPEG baru untuk validasi, ekstraksi DQT/DHT signature dan EXIF, "
        "serta penyimpanan metadata/signature ke SQLite."
    )
    st.caption(
        "Catatan: file gambar tidak disimpan sebagai BLOB di database; "
        "yang disimpan adalah metadata, signature, dan hash file."
    )

    uploaded_jpegs = st.file_uploader(
        "Pilih satu atau beberapa file JPEG",
        type=["jpg", "jpeg"],
        accept_multiple_files=True,
        key="jpeg_ingest_uploader"
    )

    if uploaded_jpegs and st.button(
        "🔍 Process and Save JPEGs",
        type="primary",
        key="process_jpeg_ingest"
    ):
        try:
            with st.spinner("Memproses JPEG dan memperbarui database..."):
                ingest_results, backup_path = ingest_uploaded_jpegs(uploaded_jpegs, DB_PATH)
            st.success("Proses ingest selesai.")
            st.caption(f"Backup database dibuat: {backup_path}")
            st.dataframe(pd.DataFrame(ingest_results), use_container_width=True, hide_index=True)
        except Exception as error:
            st.error(f"Terjadi kesalahan saat ingest: {error}")

# ==================================================
# TAB 1 — OVERVIEW
# ==================================================

with tab1:

    st.subheader("Signature Classification")

    if signatures_df is not None:

        classification_column = find_column(
            signatures_df,
            ["Classification"]
        )

        if classification_column:

            summary = (
                signatures_df[classification_column]
                .fillna("Unclassified")
                .value_counts()
                .rename_axis("Classification")
                .reset_index(name="Number of Signatures")
            )

            chart = px.bar(
                summary,
                x="Classification",
                y="Number of Signatures",
                color="Classification",
                text="Number of Signatures",
                title="Jumlah Signature Berdasarkan Kategori"
            )

            chart.update_layout(
                showlegend=False,
                xaxis_title="",
                yaxis_title="Jumlah Signature"
            )

            st.plotly_chart(
                chart,
                use_container_width=True
            )

            st.dataframe(
                summary,
                use_container_width=True,
                hide_index=True
            )

        else:
            st.warning(
                "Kolom Classification tidak ditemukan."
            )

    else:
        st.warning(
            "Tabel signature tidak ditemukan di database."
        )


    # Grafik Make kamera

    if images_df is not None and make_column:

        st.subheader("Image Distribution by Manufacturer")

        make_summary = (
            clean_text(images_df[make_column])
            .value_counts()
            .rename_axis("Make")
            .reset_index(name="Images")
        )

        make_chart = px.bar(
            make_summary,
            x="Make",
            y="Images",
            text="Images",
            title="Jumlah Gambar per Manufacturer"
        )

        st.plotly_chart(
            make_chart,
            use_container_width=True
        )


# ==================================================
# TAB 2 — SIGNATURE EXPLORER
# ==================================================

with tab2:

    st.subheader("Search and Filter JPEG Signatures")

    if signatures_df is not None:

        filtered_signatures = signatures_df.copy()

        classification_column = find_column(
            filtered_signatures,
            ["Classification"]
        )

        if classification_column:

            categories = sorted(
                clean_text(
                    filtered_signatures[classification_column]
                ).unique()
            )

            selected_categories = st.multiselect(
                "Filter Classification",
                categories,
                default=categories
            )

            filtered_signatures = filtered_signatures[
                clean_text(
                    filtered_signatures[classification_column]
                ).isin(selected_categories)
            ]


        search_signature = st.text_input(
            "Cari signature, Make, atau Model"
        )

        if search_signature:

            search_mask = (
                filtered_signatures
                .astype(str)
                .apply(
                    lambda column:
                    column.str.contains(
                        search_signature,
                        case=False,
                        na=False
                    )
                )
                .any(axis=1)
            )

            filtered_signatures = filtered_signatures[
                search_mask
            ]


        st.dataframe(
            filtered_signatures,
            use_container_width=True,
            hide_index=True
        )


        st.download_button(
            "⬇️ Download hasil filter CSV",
            filtered_signatures.to_csv(
                index=False
            ).encode("utf-8-sig"),
            file_name="filtered_jpeg_signatures.csv",
            mime="text/csv"
        )

    else:

        st.info(
            "Tabel signature belum ditemukan."
        )


# ==================================================
# TAB 3 — IMAGE AND METADATA
# ==================================================

with tab3:

    st.subheader("Image Metadata Explorer")

    if images_df is not None:

        filtered_images = images_df.copy()


        # Filter Make

        if make_column:

            makes = sorted(
                clean_text(
                    filtered_images[make_column]
                ).unique()
            )

            selected_makes = st.multiselect(
                "Filter Make",
                makes,
                default=makes
            )

            filtered_images = filtered_images[
                clean_text(
                    filtered_images[make_column]
                ).isin(selected_makes)
            ]


        # Filter Model

        if model_column:

            models = sorted(
                clean_text(
                    filtered_images[model_column]
                ).unique()
            )

            selected_models = st.multiselect(
                "Filter Model",
                models
            )

            if selected_models:

                filtered_images = filtered_images[
                    clean_text(
                        filtered_images[model_column]
                    ).isin(selected_models)
                ]


        # Search filename

        filename_column = find_column(
            filtered_images,
            ["FileName"]
        )

        search_filename = st.text_input(
            "Cari nama file JPEG"
        )

        if search_filename and filename_column:

            filtered_images = filtered_images[
                filtered_images[filename_column]
                .astype(str)
                .str.contains(
                    search_filename,
                    case=False,
                    na=False
                )
            ]


        st.dataframe(
            filtered_images,
            use_container_width=True,
            hide_index=True
        )


        st.download_button(
            "⬇️ Download metadata CSV",
            filtered_images.to_csv(
                index=False
            ).encode("utf-8-sig"),
            file_name="filtered_jpeg_metadata.csv",
            mime="text/csv"
        )

    else:

        st.info(
            "Tabel gambar belum ditemukan."
        )


# ==================================================
# TAB 4 — SQLITE DATABASE EXPLORER
# ==================================================

with tab4:

    st.subheader("SQLite Database Explorer")

    selected_table = st.selectbox(
        "Pilih tabel database",
        tables
    )

    selected_data = database_tables[
        selected_table
    ]

    st.write(
        f"Jumlah baris: {len(selected_data):,} "
        f"| Jumlah kolom: {len(selected_data.columns)}"
    )

    st.dataframe(
        selected_data,
        use_container_width=True,
        hide_index=True
    )


    st.download_button(
        "⬇️ Download tabel sebagai CSV",
        selected_data.to_csv(
            index=False
        ).encode("utf-8-sig"),
        file_name=f"{selected_table}.csv",
        mime="text/csv"
    )


# ==================================================
# SIDEBAR FOOTER
# ==================================================

st.sidebar.divider()

st.sidebar.caption(
    "JPEG-Link Database | Multimedia Forensics"
)
