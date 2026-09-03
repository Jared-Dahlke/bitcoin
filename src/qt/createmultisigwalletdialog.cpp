// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/createmultisigwalletdialog.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <addresstype.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>

#include <set>
#include <string>
#include <vector>

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QFile>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QTextStream>
#include <QVBoxLayout>

namespace {
//! Largest number of keys allowed in a P2WSH CHECKMULTISIG script.
constexpr int MAX_COSIGNERS{20};
} // namespace

CreateMultisigWalletDialog::CreateMultisigWalletDialog(QWidget* parent)
    : QDialog(parent, GUIUtil::dialog_flags)
{
    setWindowTitle(tr("Create Multisig Wallet"));

    auto* main_layout = new QVBoxLayout(this);

    auto* form = new QFormLayout();
    m_wallet_name = new QLineEdit(this);
    m_wallet_name->setObjectName("wallet_name_line_edit");
    form->addRow(tr("Wallet Name"), m_wallet_name);

    m_required_spin = new QSpinBox(this);
    m_required_spin->setObjectName("required_spinbox");
    m_required_spin->setRange(1, 2);
    m_required_spin->setValue(2);
    m_required_spin->setToolTip(tr("Number of signatures required to spend from the wallet."));
    form->addRow(tr("Required signatures"), m_required_spin);

    m_total_spin = new QSpinBox(this);
    m_total_spin->setObjectName("total_spinbox");
    m_total_spin->setRange(2, MAX_COSIGNERS);
    m_total_spin->setValue(2);
    m_total_spin->setToolTip(tr("Total number of cosigners in the wallet."));
    form->addRow(tr("Number of cosigners"), m_total_spin);

    auto* script_type_label = new QLabel(tr("Native SegWit multisig (P2WSH)"), this);
    script_type_label->setToolTip(tr("Addresses use a wsh(sortedmulti(…)) descriptor with the cosigner keys sorted per BIP 67, so every cosigner derives the same addresses regardless of key order."));
    form->addRow(tr("Address type"), script_type_label);
    main_layout->addLayout(form);

    auto* cosigner_box = new QGroupBox(tr("Cosigner keys"), this);
    auto* cosigner_box_layout = new QVBoxLayout(cosigner_box);
    auto* cosigner_hint = new QLabel(tr("Enter the extended public key of each cosigner, preferably with its key origin, e.g. [fingerprint/48h/0h/0h/2h]xpub…. The derivation to receiving and change addresses is added automatically."), cosigner_box);
    cosigner_hint->setWordWrap(true);
    cosigner_box_layout->addWidget(cosigner_hint);
    auto* scroll = new QScrollArea(cosigner_box);
    auto* scroll_widget = new QWidget(scroll);
    m_cosigner_form = new QFormLayout(scroll_widget);
    scroll->setWidget(scroll_widget);
    scroll->setWidgetResizable(true);
    scroll->setMinimumHeight(120);
    cosigner_box_layout->addWidget(scroll);
    main_layout->addWidget(cosigner_box);

    m_status_label = new QLabel(this);
    m_status_label->setObjectName("status_label");
    m_status_label->setWordWrap(true);
    main_layout->addWidget(m_status_label);

    auto* result_box = new QGroupBox(tr("Wallet descriptor"), this);
    auto* result_layout = new QVBoxLayout(result_box);
    auto* result_hint = new QLabel(tr("Every cosigner must import this same descriptor into their own wallet and verify that it derives the same first receiving address."), result_box);
    result_hint->setWordWrap(true);
    result_layout->addWidget(result_hint);
    m_descriptor_preview = new QPlainTextEdit(result_box);
    m_descriptor_preview->setObjectName("descriptor_preview");
    m_descriptor_preview->setReadOnly(true);
    m_descriptor_preview->setFont(GUIUtil::fixedPitchFont());
    m_descriptor_preview->setMaximumHeight(80);
    result_layout->addWidget(m_descriptor_preview);
    m_address_label = new QLabel(result_box);
    m_address_label->setObjectName("address_label");
    m_address_label->setFont(GUIUtil::fixedPitchFont());
    m_address_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    result_layout->addWidget(m_address_label);
    m_copy_button = new QPushButton(tr("&Copy descriptor"), result_box);
    m_copy_button->setEnabled(false);
    result_layout->addWidget(m_copy_button, 0, Qt::AlignLeft);
    main_layout->addWidget(result_box);

    m_button_box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    m_button_box->button(QDialogButtonBox::Ok)->setText(tr("Create"));
    m_button_box->button(QDialogButtonBox::Ok)->setEnabled(false);
    main_layout->addWidget(m_button_box);

    connect(m_button_box, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(m_button_box, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_copy_button, &QPushButton::clicked, this, [this] { GUIUtil::setClipboard(m_descriptor); });
    connect(m_wallet_name, &QLineEdit::textChanged, this, &CreateMultisigWalletDialog::validate);
    connect(m_required_spin, qOverload<int>(&QSpinBox::valueChanged), this, &CreateMultisigWalletDialog::validate);
    connect(m_total_spin, qOverload<int>(&QSpinBox::valueChanged), this, &CreateMultisigWalletDialog::updateCosignerRows);

    updateCosignerRows();
    GUIUtil::handleCloseWindowShortcut(this);
}

CreateMultisigWalletDialog::~CreateMultisigWalletDialog() = default;

QString CreateMultisigWalletDialog::walletName() const
{
    return m_wallet_name->text().trimmed();
}

void CreateMultisigWalletDialog::updateCosignerRows()
{
    const int total{m_total_spin->value()};
    m_required_spin->setMaximum(total);
    while (static_cast<int>(m_cosigner_edits.size()) > total) {
        m_cosigner_form->removeRow(m_cosigner_rows.back());
        m_cosigner_rows.pop_back();
        m_cosigner_edits.pop_back();
        m_cosigner_wallet_buttons.pop_back();
    }
    while (static_cast<int>(m_cosigner_edits.size()) < total) {
        auto* row = new QWidget(this);
        auto* row_layout = new QHBoxLayout(row);
        row_layout->setContentsMargins(0, 0, 0, 0);
        auto* edit = new QLineEdit(row);
        edit->setObjectName(QString("cosigner_key_edit_%1").arg(m_cosigner_edits.size()));
        edit->setFont(GUIUtil::fixedPitchFont());
        edit->setMinimumWidth(GUIUtil::TextWidth(QFontMetrics(edit->font()), QString(50, 'x')));
        edit->setPlaceholderText(QString::fromStdString("[fingerprint/48h/0h/0h/2h]xpub…"));
        connect(edit, &QLineEdit::textChanged, this, &CreateMultisigWalletDialog::validate);
        row_layout->addWidget(edit);
        auto* wallet_button = new QPushButton(tr("From wallet"), row);
        wallet_button->setToolTip(tr("Fill in a key derived from one of your loaded wallets."));
        wallet_button->setMenu(new QMenu(wallet_button));
        row_layout->addWidget(wallet_button);
        //: %1 is the number of the cosigner, e.g. "Cosigner 2".
        m_cosigner_form->addRow(tr("Cosigner %1").arg(m_cosigner_edits.size() + 1), row);
        m_cosigner_rows.push_back(row);
        m_cosigner_edits.push_back(edit);
        m_cosigner_wallet_buttons.push_back(wallet_button);
    }
    updateWalletMenus();
    validate();
}

void CreateMultisigWalletDialog::setWallets(const std::vector<WalletModel*>& wallets)
{
    m_wallet_models = wallets;
    updateWalletMenus();
}

void CreateMultisigWalletDialog::setCosignerKey(int index, const QString& key)
{
    if (index < 0 || index >= static_cast<int>(m_cosigner_edits.size())) return;
    m_cosigner_edits.at(index)->setText(key);
}

QString CreateMultisigWalletDialog::cosignerKey(int index) const
{
    if (index < 0 || index >= static_cast<int>(m_cosigner_edits.size())) return {};
    return m_cosigner_edits.at(index)->text().trimmed();
}

void CreateMultisigWalletDialog::updateWalletMenus()
{
    for (size_t i = 0; i < m_cosigner_wallet_buttons.size(); ++i) {
        QPushButton* button{m_cosigner_wallet_buttons.at(i)};
        QMenu* menu{button->menu()};
        menu->clear();
        for (WalletModel* wallet_model : m_wallet_models) {
            menu->addAction(wallet_model->getDisplayName(), this, [this, i, wallet_model] {
                Q_EMIT walletKeyRequested(static_cast<int>(i), wallet_model);
            });
        }
        if (!m_wallet_models.empty()) menu->addSeparator();
        menu->addAction(tr("From file…"), this, [this, i] {
            loadCosignerKeyFromFile(static_cast<int>(i));
        });
    }
}

void CreateMultisigWalletDialog::loadCosignerKeyFromFile(int index)
{
    const QString filename{GUIUtil::getOpenFileName(this,
        tr("Load Cosigner Key"), QString(),
        tr("Text file (*.txt)") + QLatin1String(";;") + tr("All files (*)"), nullptr)};
    if (filename.isEmpty()) return;

    QString key;
    QFile file(filename);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        // A cosigner key file holds a single short line, so only the first
        // few KB need to be considered.
        QTextStream in(&file);
        for (const QString& line : in.read(4096).split('\n')) {
            key = line.trimmed();
            if (!key.isEmpty()) break;
        }
    }
    if (key.isEmpty()) {
        QMessageBox::warning(this, tr("Load Cosigner Key"), tr("Unable to read cosigner key file."));
        return;
    }
    setCosignerKey(index, key);
}

void CreateMultisigWalletDialog::validate()
{
    m_descriptor.clear();
    m_first_address.clear();
    m_descriptor_preview->clear();
    m_address_label->clear();

    bool ok{false};
    QString status;

    std::vector<std::string> fragments;
    for (const QLineEdit* edit : m_cosigner_edits) {
        const QString text{edit->text().trimmed()};
        if (!text.isEmpty()) fragments.push_back(text.toStdString());
    }

    if (walletName().isEmpty()) {
        status = tr("Enter a name for the wallet.");
    } else if (static_cast<int>(fragments.size()) < m_total_spin->value()) {
        status = tr("Enter an extended public key for each cosigner.");
    } else {
        std::string desc{"wsh(sortedmulti(" + std::to_string(m_required_spin->value())};
        for (const std::string& fragment : fragments) {
            desc += "," + fragment + "/<0;1>/*";
        }
        desc += "))";

        FlatSigningProvider keys;
        std::string error;
        const auto parsed_descs{Parse(desc, keys, error, /*require_checksum=*/false)};
        if (parsed_descs.empty()) {
            //: %1 is a technical error message from the descriptor parser.
            status = tr("Invalid cosigner key: %1").arg(QString::fromStdString(error));
        } else if (!keys.keys.empty()) {
            status = tr("Private keys are not allowed here. Enter extended public keys only.");
        } else {
            // Detect duplicate cosigner keys by comparing the script each
            // key alone derives at the first index.
            std::set<CScript> unique_child_scripts;
            for (const std::string& fragment : fragments) {
                FlatSigningProvider frag_keys, frag_provider;
                std::string frag_error;
                std::vector<CScript> frag_scripts;
                const auto frag_descs{Parse("wpkh(" + fragment + "/0/*)", frag_keys, frag_error, /*require_checksum=*/false)};
                if (!frag_descs.empty() && frag_descs.at(0)->Expand(/*pos=*/0, frag_keys, frag_scripts, frag_provider) && !frag_scripts.empty()) {
                    unique_child_scripts.insert(frag_scripts.at(0));
                }
            }
            FlatSigningProvider provider;
            std::vector<CScript> scripts;
            if (!parsed_descs.at(0)->Expand(/*pos=*/0, keys, scripts, provider) || scripts.empty()) {
                status = tr("Unable to derive addresses from the entered keys.");
            } else if (unique_child_scripts.size() < fragments.size()) {
                status = tr("Each cosigner must use a different key.");
            } else {
                CTxDestination dest;
                ExtractDestination(scripts.at(0), dest);
                desc += "#" + GetDescriptorChecksum(desc);
                m_descriptor = QString::fromStdString(desc);
                m_first_address = QString::fromStdString(EncodeDestination(dest));
                m_descriptor_preview->setPlainText(m_descriptor);
                //: %1 is a bitcoin address.
                m_address_label->setText(tr("First receiving address: %1").arg(m_first_address));
                ok = true;
            }
        }
    }

    m_status_label->setText(status);
    m_copy_button->setEnabled(ok);
    m_button_box->button(QDialogButtonBox::Ok)->setEnabled(ok);
}
