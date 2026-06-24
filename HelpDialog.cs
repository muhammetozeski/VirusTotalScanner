using System.Drawing;

namespace VirusTotalScanner;

/// <summary>A browsable, plain-Turkish glossary of the dense signals the app shows, so the meaning of
/// "konsensüs", "nadirlik", "imza vs sezgisel" etc. is one click away — not just discoverable on hover.</summary>
internal sealed class HelpDialog : Form
{
    static readonly (string Term, string Meaning)[] Glossary =
    [
        ("Verdikt (Temiz/Şüpheli/Zararlı)", "Kaç motorun dosyayı işaretlediğine göre verilen sonuç. Eşikleri ve adları Ayarlar'dan değiştirebilirsin."),
        ("Konsensüs — büyük vs küçük motorlar", "Tespiti yapanlar büyük/itibarlı motorlar mı, yoksa yalnızca küçük motorlar mı? Sadece küçük motorlar işaretlediyse büyük olasılıkla yanlış pozitiftir."),
        ("İmza vs sezgisel/ML", "İmza eşleşmesi = bilinen bir zararlının parmak izi (kesin). Sezgisel/ML = tahmin (kesin değil). Tüm tespitler sezgiselse temkinli ol."),
        ("İlk görülme / nadirlik", "Dosyanın dünyada ilk ne zaman görüldüğü. Dakikalar önce ilk kez görülen bir dosya, yıllardır bilinen bir dosyadan daha risklidir."),
        ("Aile etiketi", "Motorların ortak adlandırdığı zararlı ailesi (ör. truva atı, fidye). Ne tür bir tehdit olduğunu özetler."),
        ("İmza güveni (İmzalı)", "Geçerli bir kod imzası = yayıncının kim olduğu doğrulandı. Bu 'temiz' garantisi DEĞİLDİR; sadece kimliği doğrular. İmzalılar kota harcamamak için VT'ye gönderilmez."),
        ("İndirme kaynağı (Zone.Identifier)", "Dosya internetten mi indirildi ve hangi siteden? İnternetten gelen dosyalar daha dikkatli incelenmeli."),
        ("Davranış / yetenek özeti", "Dosyanın ne yaptığı: ağ iletişimi, kalıcılık, anti-analiz, tuş kaydı vb. (VT etiketlerinden, çalıştırmadan)."),
        ("Overlay (imza sonrası ek bayt)", "İmzalı bir dosyaya imzadan sonra eklenmiş veri. Kurulumcularda normaldir ama doldurulmuş/trojanlı bir dosyanın işareti de olabilir."),
        ("Eski imza (stale)", "Tespit aylarca eski imzalardan geliyorsa, güncel motorlarla yeniden denetlemek mantıklı olabilir."),
        ("Karantina (.VIRUS)", "Şüpheli dosyanın uzantısını .VIRUS yaparak çalıştırılamaz hale getirir. Geri dönüşü vardır — Karantina kasasından geri yükleyebilirsin."),
        ("Anahtarsız (GUI) mod", "API anahtarı yerine gizli bir tarayıcı ile VT'nin web arayüzünü kullanır: kotasız ama daha yavaş."),
    ];

    public HelpDialog()
    {
        Text = "❓ Yardım — sinyaller ne anlama geliyor?";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(680, 560);
        MinimumSize = new Size(480, 360);

        var box = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            DetectUrls = false,
            Font = new Font("Segoe UI", 10f),
            Margin = new Padding(0),
        };

        var close = new Button { Text = "Kapat", DialogResult = DialogResult.OK, Dock = DockStyle.Right, Width = 100 };
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(10, 7, 10, 7) };
        bottom.Controls.Add(close);
        var pad = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 12, 14, 4) };
        pad.Controls.Add(box);

        Controls.Add(pad);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleButton(close);

        var t = Theme.Current;
        box.BackColor = t.Panel;
        box.ForeColor = t.Text;
        foreach (var (term, meaning) in Glossary)
        {
            box.SelectionFont = new Font("Segoe UI", 10.5f, FontStyle.Bold);
            box.SelectionColor = t.Accent;
            box.AppendText(term + "\n");
            box.SelectionFont = new Font("Segoe UI", 10f, FontStyle.Regular);
            box.SelectionColor = t.Text;
            box.AppendText(meaning + "\n\n");
        }
        box.SelectionStart = 0;
        box.ScrollToCaret();
    }
}
